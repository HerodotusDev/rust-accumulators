//! Draft consistency-proof suite over SQLite: the async draft's
//! `consistency_proof` / `verify_consistency` against the brute-force
//! reference oracle — appended-only, edited, and nullifying buffers,
//! `Optimise` independence, single-batched-read generation, typed
//! rejections, and byte-level cross-checks against the sync MMR's proofs
//! on the equivalent committed state.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(
    feature = "draft_mmr",
    feature = "sqlite",
    feature = "keccak_sol",
    not(target_family = "wasm")
))]

#[path = "common/mod.rs"]
mod common;

use accumulators::hashers::{Hasher, KeccakSolHasher};
use accumulators::mmr::{
    AsyncDraft, AsyncMmr, ConsistencyProof, Editable, LeafCount, MmrError, MmrSize, Nullifying,
    Optimise, Plain, WithPeaks, verify_consistency_proof,
};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::memory::InMemoryStore;
use accumulators::store::sqlite::SqliteStore;
use accumulators::utils::mmr::size_of;

use common::{
    FaultyStore, TempDb, composed_hashes, element, elements, flipped, id, leaf_hashes, node_sizes,
    prefix_roots, root_of_hashes, slices,
};

type TestMmr = AsyncMmr<KeccakSolHasher, SqliteStore>;
type TestMmrEdit = AsyncMmr<KeccakSolHasher, SqliteStore, Plain, Editable>;
type TestMmrNull = AsyncMmr<KeccakSolHasher, SqliteStore, Plain, Nullifying>;
type ProofOf = ConsistencyProof<Hash>;

// ---------------------------------------------------------------- helpers

fn hasher() -> KeccakSolHasher {
    KeccakSolHasher
}

async fn fresh(label: &str) -> (TempDb, SqliteStore) {
    let db = TempDb::new(label);
    let store = SqliteStore::connect(db.path()).await.expect("connect");
    (db, store)
}

// ----------------------------------------------------------- appended-only

mod appended_only {
    use super::*;

    /// Every prefix pair of an append-only draft verifies against the flat
    /// reference — including the degenerate empty and trivial prefixes. A
    /// draft's target size is its current composed size, so each `m`
    /// restarts the draft with `m − BASE` appends.
    #[tokio::test]
    async fn every_prefix_pair_verifies() {
        const BASE: usize = 12;
        const TOTAL: usize = 24;
        let h = hasher();
        let (_db, store) = fresh("draft-consistency-append").await;
        let mut base = TestMmr::create(h, store, id(40)).await.expect("create");
        for el in &elements(BASE as u64) {
            base.append(el).await.expect("append must succeed");
        }

        let hashes = composed_hashes(&h, TOTAL, &[], &[]);
        let roots = prefix_roots(&h, &hashes);
        let sizes = node_sizes(TOTAL);
        for m in BASE..=TOTAL {
            let mut draft = base.start_draft();
            for i in BASE..m {
                draft.append(&element(i as u64)).expect("draft append");
            }
            assert_eq!(draft.leaf_count(), LeafCount::new(m as u64));
            for n in 0..=m {
                let proof = draft
                    .consistency_proof(sizes[n])
                    .await
                    .unwrap_or_else(|error| panic!("consistency ({n}, {m}) failed: {error}"));
                assert_eq!(proof.prev_size, sizes[n]);
                assert_eq!(proof.size, sizes[m]);
                assert!(
                    matches!(
                        verify_consistency_proof(&h, &proof, roots[n], roots[m]),
                        Ok(true)
                    ),
                    "consistency ({n}, {m}) must verify"
                );
            }
        }
    }

    /// Generation is exactly one batched store read for a general pair, and
    /// zero reads for the degenerate sizes served from the composed peaks.
    #[tokio::test]
    async fn generation_is_one_batched_read() {
        let h = hasher();
        let (_db, sqlite) = fresh("draft-consistency-reads").await;
        let store = FaultyStore::new(sqlite);
        let probe = store.clone();
        let mut base: AsyncMmr<KeccakSolHasher, FaultyStore<SqliteStore>> =
            AsyncMmr::create(h, store, id(41)).await.expect("create");
        for el in &elements(20) {
            base.append(el).await.expect("append must succeed");
        }

        let mut draft = base.start_draft();
        for i in 20..24_u64 {
            draft.append(&element(i)).expect("draft append");
        }
        let _ = draft
            .consistency_proof(size_of(LeafCount::new(7)))
            .await
            .expect("general pair must generate");
        assert_eq!(
            probe.fault().read_calls(),
            1,
            "a general consistency proof is exactly one batched read"
        );

        let _ = draft
            .consistency_proof(size_of(LeafCount::new(24)))
            .await
            .expect("trivial prefix must generate");
        let _ = draft
            .consistency_proof(MmrSize::ZERO)
            .await
            .expect("empty prefix must generate");
        assert_eq!(
            probe.fault().read_calls(),
            1,
            "degenerate sizes are served from the composed peaks: no reads"
        );
    }
}

// ------------------------------------------------------------------ edits

mod edited {
    use super::*;

    /// A draft with buffered updates and deletes: every prefix pair
    /// verifies against the *effective* (edited) oracle, and the proofs
    /// commit the buffered values — the unedited flat roots are rejected.
    #[tokio::test]
    async fn prefixes_carry_the_buffered_values() {
        const BASE: usize = 8;
        const TOTAL: usize = 12;
        let h = hasher();
        let (_db, store) = fresh("draft-consistency-edited").await;
        let mut base = TestMmrEdit::create_editable(h, store, id(42))
            .await
            .expect("create");
        for el in &elements(BASE as u64) {
            base.append(el).await.expect("append must succeed");
        }

        let mut effective: Vec<Hash> = leaf_hashes(&h, &slices(&elements(BASE as u64)))
            .into_iter()
            .collect();
        effective[2] = h.hash_leaf(b"updated-2").expect("valid element");
        effective[5] = h.genesis();
        for i in BASE..TOTAL {
            effective.push(if i == BASE + 2 {
                h.hash_leaf(b"updated-10").expect("valid element")
            } else {
                h.hash_leaf(&element(i as u64)).expect("valid element")
            });
        }
        let roots = prefix_roots(&h, &effective);
        let sizes = node_sizes(TOTAL);

        for m in BASE..=TOTAL {
            let mut draft = base.start_draft();
            draft
                .update(LeafIndex::new(2), b"updated-2", None)
                .await
                .expect("buffer update");
            draft
                .delete(LeafIndex::new(5), None)
                .await
                .expect("buffer delete");
            for i in BASE..m {
                draft.append(&element(i as u64)).expect("draft append");
            }
            if m > BASE + 2 {
                draft
                    .update(LeafIndex::new((BASE + 2) as u64), b"updated-10", None)
                    .await
                    .expect("buffer update on a draft leaf");
            }
            for n in 0..=m {
                let proof = draft
                    .consistency_proof(sizes[n])
                    .await
                    .unwrap_or_else(|error| panic!("consistency ({n}, {m}) failed: {error}"));
                assert!(
                    matches!(
                        verify_consistency_proof(&h, &proof, roots[n], roots[m]),
                        Ok(true)
                    ),
                    "consistency ({n}, {m}) must verify against the edited oracle"
                );
            }
        }

        // The prefix statement is about the composed values *now*: against
        // the unedited flat history the same proof does not verify.
        let unedited: Vec<Hash> = leaf_hashes(&h, &slices(&elements(TOTAL as u64)))
            .into_iter()
            .collect();
        let flat = prefix_roots(&h, &unedited);
        let mut draft = base.start_draft();
        draft
            .update(LeafIndex::new(2), b"updated-2", None)
            .await
            .expect("buffer update");
        let proof = draft.consistency_proof(sizes[6]).await.expect("generate");
        assert!(
            matches!(
                verify_consistency_proof(&h, &proof, flat[6], roots[TOTAL]),
                Ok(false)
            ),
            "the unedited earlier root must not verify"
        );
    }
}

// ------------------------------------------------------------ nullifying

mod nullified {
    use super::*;

    /// Nullifications change no node values and no records are consulted:
    /// the prefix statement over a nullifying draft's buffer is the plain
    /// flat history (the replace's append included).
    #[tokio::test]
    async fn nullifications_do_not_disturb_the_prefix_statement() {
        const BASE: usize = 8;
        const TOTAL: usize = 12;
        let h = hasher();
        let (_db, store) = fresh("draft-consistency-nullified").await;
        let mut base = TestMmrNull::create_nullifying(h, store, id(43))
            .await
            .expect("create");
        for el in &elements(BASE as u64) {
            base.append(el).await.expect("append must succeed");
        }

        // Effective leaf values: nullified leaves keep their node values;
        // the replace appends element(100), then plain appends.
        let mut effective: Vec<Hash> = leaf_hashes(&h, &slices(&elements(BASE as u64)))
            .into_iter()
            .collect();
        effective.push(h.hash_leaf(&element(100)).expect("valid element"));
        for i in BASE..TOTAL - 1 {
            effective.push(h.hash_leaf(&element(i as u64)).expect("valid element"));
        }
        let roots = prefix_roots(&h, &effective);
        let sizes = node_sizes(TOTAL);

        let mut draft = base.start_draft();
        draft
            .nullify_shallow(LeafIndex::new(1))
            .expect("buffer nullify");
        draft
            .replace_shallow(LeafIndex::new(4), &element(100))
            .expect("buffer replace");
        for i in BASE..TOTAL - 1 {
            draft.append(&element(i as u64)).expect("draft append");
        }
        for n in 0..=TOTAL {
            let proof = draft
                .consistency_proof(sizes[n])
                .await
                .unwrap_or_else(|error| panic!("consistency ({n}, {TOTAL}) failed: {error}"));
            assert!(
                matches!(
                    verify_consistency_proof(&h, &proof, roots[n], roots[TOTAL]),
                    Ok(true)
                ),
                "consistency ({n}, {TOTAL}) must verify"
            );
        }
    }
}

// -------------------------------------------------------------- optimise

mod optimise {
    use super::*;

    /// `Optimise::On` folds the log at commit, but the composed view is the
    /// buffer-time fold in order: pre-commit proofs commit the composed
    /// shape, the committed handles' proofs match their own shapes, and the
    /// `Off`-committed handle reproduces the draft's proofs byte-for-byte.
    #[tokio::test]
    async fn composed_proofs_are_independent_of_the_replay_strategy() {
        async fn base_of_six(h: KeccakSolHasher, store: SqliteStore, byte: u8) -> TestMmrEdit {
            let mut base = TestMmrEdit::create_editable(h, store, id(byte))
                .await
                .expect("create");
            for el in &elements(6) {
                base.append(el).await.expect("append must succeed");
            }
            base
        }

        // append(6), delete(6), append(7): the fold annihilates the first
        // append, the composed view keeps it (as genesis).
        async fn buffer_annihilating_log(
            draft: &mut AsyncDraft<'_, KeccakSolHasher, SqliteStore, Plain, Editable>,
        ) {
            draft.append(&element(6)).expect("draft append");
            draft
                .delete(LeafIndex::new(6), None)
                .await
                .expect("buffer delete");
            draft.append(&element(7)).expect("draft append");
        }

        let h = hasher();
        // The composed view: 8 leaves — leaf 6 is genesis (deleted),
        // leaf 7 is element(7).
        let mut composed: Vec<Hash> = leaf_hashes(&h, &slices(&elements(6))).into_iter().collect();
        composed.push(h.genesis());
        composed.push(h.hash_leaf(&element(7)).expect("valid element"));
        let composed_roots = prefix_roots(&h, &composed);
        let composed_sizes = node_sizes(8);

        // Off: the committed handle reproduces the composed shape
        // byte-for-byte, for every prefix pair.
        let (_db, store) = fresh("draft-consistency-opt-off").await;
        let mut base_off = base_of_six(h, store, 44).await;
        let mut draft = base_off.start_draft();
        buffer_annihilating_log(&mut draft).await;
        assert_eq!(draft.leaf_count(), LeafCount::new(8));
        let mut off_proofs: Vec<ProofOf> = Vec::new();
        for size in composed_sizes.iter().take(9) {
            off_proofs.push(draft.consistency_proof(*size).await.expect("generate"));
        }
        draft.commit(Optimise::Off).await.expect("commit");
        for (n, proof) in off_proofs.iter().enumerate() {
            assert_eq!(
                &base_off
                    .consistency_proof(composed_sizes[n])
                    .await
                    .expect("generate"),
                proof,
                "the committed handle serves the same proof as the draft ({n}, 8)"
            );
            assert!(matches!(
                verify_consistency_proof(&h, proof, composed_roots[n], composed_roots[8]),
                Ok(true)
            ));
        }

        // On: the fold erases the annihilated append — the committed shape
        // is 7 leaves with element(7) at leaf 6, so the composed proofs no
        // longer match the handle's, and the handle's verify against the
        // folded oracle.
        let folded_roots = prefix_roots(&h, &composed_hashes(&h, 6, &[], &[element(7)]));
        let (_db, store) = fresh("draft-consistency-opt-on").await;
        let mut base_on = base_of_six(h, store, 45).await;
        let mut draft = base_on.start_draft();
        buffer_annihilating_log(&mut draft).await;
        let composed_proof = draft
            .consistency_proof(composed_sizes[4])
            .await
            .expect("generate");
        draft.commit(Optimise::On).await.expect("commit");
        assert_eq!(
            base_on.leaf_count(),
            LeafCount::new(7),
            "the fold erased one leaf"
        );
        let committed_proof = base_on
            .consistency_proof(size_of(LeafCount::new(4)))
            .await
            .expect("generate");
        assert_ne!(
            committed_proof, composed_proof,
            "the folded shape differs from the composed shape"
        );
        assert!(matches!(
            verify_consistency_proof(&h, &committed_proof, folded_roots[4], folded_roots[7]),
            Ok(true)
        ));
    }
}

// ------------------------------------------------------------ cross-check

mod cross_check {
    use super::*;

    /// The async draft's proofs over SQLite are byte-identical to the sync
    /// MMR's proofs over the equivalent committed state (memory store):
    /// same hasher, same layout, same node values — the backend is
    /// invisible to the commitment.
    #[tokio::test]
    async fn draft_proofs_equal_the_sync_committed_mmr_proofs() {
        const BASE: usize = 5;
        let h = hasher();

        let (_db, store) = fresh("draft-consistency-cross").await;
        let mut async_base = TestMmrEdit::create_editable(h, store, id(46))
            .await
            .expect("create");
        for el in &elements(BASE as u64) {
            async_base.append(el).await.expect("append must succeed");
        }
        let mut draft = async_base.start_draft();
        draft
            .update(LeafIndex::new(1), b"rewritten", None)
            .await
            .expect("buffer update");
        for i in BASE..BASE + 3 {
            draft.append(&element(i as u64)).expect("draft append");
        }
        let total = BASE + 3;
        let sizes = node_sizes(total);
        let mut draft_proofs: Vec<ProofOf> = Vec::new();
        for size in sizes.iter().take(total + 1) {
            draft_proofs.push(draft.consistency_proof(*size).await.expect("generate"));
        }
        drop(draft);

        // The equivalent committed sync MMR: same base, same buffered ops,
        // replayed in order (the Off replay).
        let mut sync_mmr: accumulators::mmr::Mmr<KeccakSolHasher, InMemoryStore, Plain, Editable> =
            accumulators::mmr::Mmr::create_editable(h, InMemoryStore::new(), id(47))
                .expect("create");
        for el in &elements(BASE as u64) {
            sync_mmr.append(el).expect("append must succeed");
        }
        sync_mmr
            .update(LeafIndex::new(1), b"rewritten", None)
            .expect("update");
        for i in BASE..BASE + 3 {
            sync_mmr.append(&element(i as u64)).expect("append");
        }

        for (n, draft_proof) in draft_proofs.iter().enumerate() {
            assert_eq!(
                &sync_mmr.consistency_proof(sizes[n]).expect("generate"),
                draft_proof,
                "sync and draft proofs agree on the equivalent state ({n}, {total})"
            );
        }
    }
}

// -------------------------------------------------------------- rejection

mod rejection {
    use super::*;

    /// Degenerate anchors, the draft-level verifier, and the typed
    /// rejections: tampered anchors are `Ok(false)`, fabricated structure
    /// is a typed error, out-of-range and malformed sizes are
    /// `InvalidPrevSize`.
    #[tokio::test]
    async fn degenerate_verify_and_rejections() {
        let h = hasher();
        let (_db, store) = fresh("draft-consistency-reject").await;
        let mut base = TestMmrEdit::create_editable(h, store, id(48))
            .await
            .expect("create");
        for el in &elements(10) {
            base.append(el).await.expect("append must succeed");
        }
        let mut draft = base.start_draft();
        draft
            .update(LeafIndex::new(3), b"updated-3", None)
            .await
            .expect("buffer update");
        for i in 10..14_u64 {
            draft.append(&element(i)).expect("draft append");
        }

        let hashes = composed_hashes(
            &h,
            10,
            &[(3, Some(b"updated-3".to_vec()))],
            &[element(10), element(11), element(12), element(13)],
        );
        let roots = prefix_roots(&h, &hashes);
        let sizes = node_sizes(14);

        // Empty prefix and trivial prefix, from the composed peaks alone.
        let empty_root = root_of_hashes(&h, &[]);
        let proof = draft
            .consistency_proof(MmrSize::ZERO)
            .await
            .expect("generate");
        assert_eq!(proof.prev_peaks, [] as [Hash; 0]);
        assert!(matches!(
            verify_consistency_proof(&h, &proof, empty_root, roots[14]),
            Ok(true)
        ));
        let trivial = draft.consistency_proof(sizes[14]).await.expect("generate");
        assert_eq!(trivial.path, [] as [Hash; 0]);
        assert!(matches!(
            verify_consistency_proof(&h, &trivial, roots[14], roots[14]),
            Ok(true)
        ));

        // The draft-level verifier: positive, then tampered anchors.
        let proof = draft.consistency_proof(sizes[5]).await.expect("generate");
        assert!(draft.verify_consistency(&proof, roots[5]).expect("verify"));
        assert!(matches!(
            draft.verify_consistency(&proof, flipped(roots[5])),
            Ok(false)
        ));
        // A proof committed to the pre-draft state misses the composed
        // target root.
        drop(draft);
        let stale = base.consistency_proof(sizes[5]).await.expect("generate");
        let draft = base.start_draft();
        assert!(matches!(
            draft.verify_consistency(&stale, roots[5]),
            Ok(false)
        ));
        drop(draft);

        // Structural fabrication: truncated path is a typed error.
        let mut truncated = proof;
        truncated.path.pop();
        assert!(matches!(
            verify_consistency_proof(&h, &truncated, roots[5], roots[14]),
            Err(accumulators::mmr::VerifyError::Inconsistent(_))
        ));

        // Out of range, and a malformed (non-well-formed) size.
        let draft = base.start_draft();
        assert!(matches!(
            draft.consistency_proof(size_of(LeafCount::new(15))).await,
            Err(MmrError::InvalidPrevSize { .. })
        ));
        assert!(matches!(
            draft.consistency_proof(MmrSize::new_unchecked(5)).await,
            Err(MmrError::InvalidPrevSize { .. })
        ));
    }

    /// A `WithPeaks` base keeps its seed floor under a draft: below the
    /// floor is a typed rejection; the empty prefix and the floor itself
    /// are servable and verify against the flat reference.
    #[tokio::test]
    async fn withpeaks_floor_survives_the_draft() {
        let h = hasher();
        let (_db, store) = fresh("draft-consistency-floor").await;
        let mut seed_base = TestMmr::create(h, store.clone(), id(49))
            .await
            .expect("create");
        for el in &elements(6) {
            seed_base.append(el).await.expect("append must succeed");
        }
        let seed = seed_base.size();
        let seed_peaks = seed_base.peaks().to_vec();
        drop(seed_base);

        let mut peaks_mmr: AsyncMmr<KeccakSolHasher, SqliteStore, WithPeaks> =
            AsyncMmr::from_peaks(h, store, id(49), seed, &seed_peaks)
                .await
                .expect("seed succeeds");
        for i in 6..9_u64 {
            peaks_mmr.append(&element(i)).await.expect("append");
        }

        let mut draft = peaks_mmr.start_draft();
        draft.append(&element(9)).expect("draft append");

        let hashes = composed_hashes(&h, 10, &[], &[]);
        let roots = prefix_roots(&h, &hashes);
        let sizes = node_sizes(10);
        for n in [0_usize, 6, 7, 9, 10] {
            let proof = draft
                .consistency_proof(sizes[n])
                .await
                .unwrap_or_else(|error| panic!("consistency from {n} failed: {error}"));
            let prev_root = if n == 0 {
                root_of_hashes(&h, &[])
            } else {
                roots[n]
            };
            assert!(
                matches!(
                    verify_consistency_proof(&h, &proof, prev_root, roots[10]),
                    Ok(true)
                ),
                "consistency ({n}, 10) must verify"
            );
        }
        assert!(matches!(
            draft.consistency_proof(sizes[3]).await,
            Err(MmrError::InvalidPrevSize { .. })
        ));
    }
}
