//! Property-based tests: the draft op-log as a state
//! machine against a plain reference model, the `Optimise` semantics
//! properties, proof-encoding invariants, and the key codec round trip.
//!
//! The reference models here are deliberately naive — a `Vec` of slots plus
//! the nullifier/aliveness rules as documented in the `Optimise` docs —
//! never a re-implementation of the crate's fold internals.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(
    feature = "mmr",
    feature = "memory",
    feature = "draft_mmr",
    feature = "keccak_sol"
))]

#[path = "common/mod.rs"]
mod common;

use proptest::prelude::*;
use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};

use accumulators::hashers::{Hasher, KeccakSolHasher};
use accumulators::ids::AccumulatorId;
use accumulators::mmr::proof::encoding::{EncodedMultiProof, EncodedProof, HexStyle};
use accumulators::mmr::{Draft, Editable, FixedWidth, Mmr, Optimise, Plain, ProofEncoding};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::keys::{self, Table};
use accumulators::store::memory::InMemoryStore;

use common::{root_of_hashes, slices};

const H: KeccakSolHasher = KeccakSolHasher;
const BASE_LEN: u64 = 3;
const ID_BYTE: u8 = 0x2a;

fn id() -> AccumulatorId {
    AccumulatorId::from_bytes([ID_BYTE; 16])
}

/// One leaf in the reference model: the element preimage (the honest
/// preimage — never a hash re-derived from the subject) or the deleted
/// marker, whose stored hash is by contract the hasher's genesis value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Slot {
    Element(Vec<u8>),
    Deleted,
}

impl Slot {
    fn hash(&self) -> Hash {
        match self {
            Self::Element(element) => H.hash_leaf(element).expect("model elements are valid"),
            Self::Deleted => H.genesis(),
        }
    }
}

fn base_slots() -> Vec<Slot> {
    (0..BASE_LEN)
        .map(|index| Slot::Element(format!("base-{index}").into_bytes()))
        .collect()
}

/// The expected leaf-hash vector of a model state, base first.
fn expected_hashes(slots: &[Slot]) -> Vec<Hash> {
    slots.iter().map(Slot::hash).collect()
}

// -------------------------------------------------- property 1: draft model

/// The draft op-log reference state machine: a plain `Vec<Slot>`. Transitions
/// are generated FROM the current state, so every generated op is in range by
/// construction — no out-of-range ops to filter on the system side.
#[derive(Debug)]
struct LogModel;

impl ReferenceStateMachine for LogModel {
    type State = Vec<Slot>;
    type Transition = DraftOp;

    fn init_state() -> BoxedStrategy<Self::State> {
        Just(base_slots()).boxed()
    }

    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        let element = prop::collection::vec(any::<u8>(), 1..8);
        let len = state.len() as u64;
        if len == 0 {
            element.prop_map(DraftOp::Append).boxed()
        } else {
            prop_oneof![
                // Weight edits and appends roughly evenly; targets are always
                // valid leaves of the current composed state.
                (0..len, element.clone())
                    .prop_map(|(leaf, element)| DraftOp::Update(leaf, element)),
                (0..len, element.clone())
                    .prop_map(|(leaf, element)| DraftOp::DeleteThenUpdate(leaf, element)),
                (0..len).prop_map(DraftOp::Delete),
                element.prop_map(DraftOp::Append),
            ]
            .boxed()
        }
    }

    fn apply(mut state: Self::State, transition: &Self::Transition) -> Self::State {
        match transition {
            DraftOp::Append(element) => state.push(Slot::Element(element.clone())),
            DraftOp::Update(leaf, element)
            // A delete followed by a re-occupying update: the model collapses
            // it to the final value in place (the slot never disappears).
            | DraftOp::DeleteThenUpdate(leaf, element) => {
                state[usize::try_from(*leaf).expect("leaf fits usize")] =
                    Slot::Element(element.clone());
            }
            DraftOp::Delete(leaf) => {
                state[usize::try_from(*leaf).expect("leaf fits usize")] = Slot::Deleted;
            }
        }
        state
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DraftOp {
    Append(Vec<u8>),
    Update(u64, Vec<u8>),
    Delete(u64),
    /// Delete immediately followed by an update of the same leaf — exercises
    /// the edit-chain fold without annihilating the leaf.
    DeleteThenUpdate(u64, Vec<u8>),
}

/// The system under test: a real editable MMR. Every transition is applied
/// through a fresh draft, whose composed read surface must equal the model,
/// and committed with `Optimise::Off` — after which the committed base must
/// equal the model too.
struct DraftDriver {
    mmr: Mmr<KeccakSolHasher, InMemoryStore, Plain, Editable>,
}

impl DraftDriver {
    /// Asserts the draft's composed read surface (leaf count, root, peaks,
    /// per-leaf hashes, a proof) against the reference model.
    fn assert_read_parity(
        draft: &Draft<'_, KeccakSolHasher, InMemoryStore, Plain, Editable>,
        model: &[Slot],
    ) {
        assert_eq!(
            draft.leaf_count().get(),
            model.len() as u64,
            "the composed leaf count must equal the model"
        );
        assert_eq!(
            draft.root(),
            root_of_hashes(&H, &expected_hashes(model)),
            "the composed root must equal the model's root"
        );
        if !model.is_empty() {
            let leaf = LeafIndex::new((model.len() - 1) as u64);
            let proof = draft.proof(leaf).expect("the last leaf proves");
            assert_eq!(
                proof.element_hash,
                model[usize::try_from(leaf.get()).expect("fits")].hash(),
                "the proof must commit to the model's leaf value"
            );
        }
    }

    /// Asserts the committed base state equals the model.
    fn assert_committed_parity(&self, model: &[Slot]) {
        assert_eq!(self.mmr.leaf_count().get(), model.len() as u64);
        assert_eq!(self.mmr.root(), root_of_hashes(&H, &expected_hashes(model)));
        for (leaf, slot) in model.iter().enumerate() {
            assert_eq!(
                self.mmr
                    .leaf_hash(LeafIndex::new(leaf as u64))
                    .expect("leaf_hash on a valid leaf"),
                Some(slot.hash()),
                "committed leaf {leaf} must equal the model"
            );
        }
    }
}

impl StateMachineTest for DraftDriver {
    type SystemUnderTest = Self;
    type Reference = LogModel;

    fn init_test(ref_state: &Vec<Slot>) -> Self {
        let _ = ref_state;
        let mut mmr = Mmr::<KeccakSolHasher, InMemoryStore, Plain, Editable>::create_editable(
            H,
            InMemoryStore::new(),
            id(),
        )
        .expect("create must succeed");
        for slot in base_slots() {
            let Slot::Element(element) = slot else {
                unreachable!("the base slots are elements by construction")
            };
            mmr.append(&element).expect("the base append must succeed");
        }
        Self { mmr }
    }

    fn apply(
        state: Self::SystemUnderTest,
        ref_state: &Vec<Slot>,
        transition: DraftOp,
    ) -> Self::SystemUnderTest {
        let mut driver = state;
        let mut draft = driver.mmr.start_draft();
        match &transition {
            DraftOp::Append(element) => {
                draft.append(element).expect("buffer append");
            }
            DraftOp::Update(leaf, element) => {
                draft
                    .update(LeafIndex::new(*leaf), element, None)
                    .expect("buffer update");
            }
            DraftOp::Delete(leaf) => {
                draft
                    .delete(LeafIndex::new(*leaf), None)
                    .expect("buffer delete");
            }
            DraftOp::DeleteThenUpdate(leaf, element) => {
                draft
                    .delete(LeafIndex::new(*leaf), None)
                    .expect("buffer delete");
                draft
                    .update(LeafIndex::new(*leaf), element, None)
                    .expect("buffer re-update");
            }
        }
        Self::assert_read_parity(&draft, ref_state);
        match draft.commit(Optimise::Off) {
            Ok(_) => {}
            Err(failure) => panic!("an in-range log must commit: {:?}", failure.error),
        }
        driver.assert_committed_parity(ref_state);
        driver
    }

    fn check_invariants(state: &Self::SystemUnderTest, ref_state: &Vec<Slot>) {
        assert_eq!(
            state.mmr.leaf_count().get(),
            ref_state.len() as u64,
            "the committed leaf count must track the model after every step"
        );
    }
}

prop_state_machine! {
    #![proptest_config(proptest::test_runner::Config::with_cases(256))]
    #[test]
    fn the_draft_log_matches_the_reference_model(sequential 1..24 => DraftDriver);
}

// ------------------------------------------------ property 2: Optimise modes

/// A flat op-log strategy for the `Optimise` properties. Target indexes may
/// point past the current composed leaf count — the replay skips such ops
/// (they cannot be buffered), exactly like the model does.
fn op_log() -> impl Strategy<Value = Vec<DraftOp>> {
    let element = prop::collection::vec(any::<u8>(), 1..8);
    prop::collection::vec(
        prop_oneof![
            element.clone().prop_map(DraftOp::Append),
            (0..=BASE_LEN + 8_u64, element)
                .prop_map(|(leaf, element)| DraftOp::Update(leaf, element)),
            (0..=BASE_LEN + 8_u64).prop_map(DraftOp::Delete),
        ],
        0..40,
    )
}

/// The committed state of an MMR as an observable vector: the leaf hashes in
/// leaf order plus the root — the equality surface for both `Optimise`
/// strategies.
fn committed_state(
    mmr: &Mmr<KeccakSolHasher, InMemoryStore, Plain, Editable>,
) -> (Vec<Hash>, Hash) {
    let hashes: Vec<Hash> = (0..mmr.leaf_count().get())
        .map(|leaf| {
            mmr.leaf_hash(LeafIndex::new(leaf))
                .expect("leaf_hash on a valid leaf")
                .expect("committed leaves are occupied or genesis-cleared")
        })
        .collect();
    (hashes, mmr.root())
}

/// Replays `ops` through a real draft over a fresh base, skipping ops that
/// cannot be buffered (target beyond the composed leaf count), then commits
/// with `optimise`.
fn replay(ops: &[DraftOp], optimise: Optimise) -> (Vec<Hash>, Hash) {
    let mut mmr = Mmr::<KeccakSolHasher, InMemoryStore, Plain, Editable>::create_editable(
        H,
        InMemoryStore::new(),
        id(),
    )
    .expect("create must succeed");
    for slot in base_slots() {
        let Slot::Element(element) = slot else {
            unreachable!("the base slots are elements by construction")
        };
        mmr.append(&element).expect("the base append must succeed");
    }

    let mut draft = mmr.start_draft();
    let mut composed_len = BASE_LEN;
    for op in ops {
        match op {
            DraftOp::Append(_) => {
                draft.append(b"x").expect("buffer append");
                composed_len += 1;
            }
            DraftOp::Update(leaf, element) if *leaf < composed_len => draft
                .update(LeafIndex::new(*leaf), element, None)
                .expect("buffer update"),
            DraftOp::Delete(leaf) if *leaf < composed_len => draft
                .delete(LeafIndex::new(*leaf), None)
                .expect("buffer delete"),
            _ => {}
        }
    }
    match draft.commit(optimise) {
        Ok(_) => {}
        Err(failure) => panic!("a gate-free log must commit: {:?}", failure.error),
    }
    committed_state(&mmr)
}

/// The two reference models, computed naively side by side:
///
/// - `off`: sequential replay — every append lands, deletes clear to genesis
///   (the `Optimise::Off` semantics);
/// - `on`: net-effect replay — a draft-appended leaf that is deleted in the
///   same log vanishes (append + delete annihilate), a later update
///   re-occupies it; pre-existing leaves never vanish (documented on
///   `Optimise::On`).
///
/// Returns the `off` model, the `on` model, and whether any draft append was
/// annihilated without resurrection (the documented `On ≠ Off` divergence).
fn models(ops: &[DraftOp]) -> (Vec<Hash>, Hash, Vec<Hash>, Hash, bool) {
    let mut off: Vec<Slot> = base_slots();
    let mut on_base: Vec<Slot> = base_slots();
    // The `on` model: surviving appends in fold order, tombstoned when
    // annihilated. A resurrected (annihilated, later updated) draft append
    // re-enters at the END of the folded log — the fold processes ops
    // sequentially, so the re-occupying update appends after every folded op
    // seen so far.
    let mut on_committed: Vec<Option<Vec<u8>>> = Vec::new();
    // Logical draft position → slot in `on_committed` (`None` = annihilated).
    let mut on_map: Vec<Option<usize>> = Vec::new();
    let base_len = usize::try_from(BASE_LEN).expect("BASE_LEN fits usize");
    let mut composed_len = BASE_LEN;
    let mut annihilated = false;

    for op in ops {
        match op {
            DraftOp::Append(_) => {
                // The replayed element is a stand-in (b"x"): the model only
                // needs the leaf's existence; hashes come from the real run.
                off.push(Slot::Element(b"x".to_vec()));
                on_map.push(Some(on_committed.len()));
                on_committed.push(Some(b"x".to_vec()));
                composed_len += 1;
            }
            DraftOp::Update(leaf, element) if *leaf < composed_len => {
                let index = usize::try_from(*leaf).expect("fits");
                if index < base_len {
                    off[index] = Slot::Element(element.clone());
                    on_base[index] = Slot::Element(element.clone());
                } else {
                    // Off semantics: the update rewrites the draft leaf in
                    // place (draft leaves never shift under Off).
                    off[index] = Slot::Element(element.clone());
                    let position = index - base_len;
                    match on_map.get_mut(position) {
                        Some(Some(slot)) => on_committed[*slot] = Some(element.clone()),
                        Some(slot @ None) => {
                            // Resurrection: the re-occupying update appends
                            // at the end of the folded log.
                            *slot = Some(on_committed.len());
                            on_committed.push(Some(element.clone()));
                        }
                        None => {}
                    }
                }
            }
            DraftOp::Delete(leaf) if *leaf < composed_len => {
                let index = usize::try_from(*leaf).expect("fits");
                if index < base_len {
                    off[index] = Slot::Deleted;
                    on_base[index] = Slot::Deleted;
                } else {
                    // Off semantics: the draft leaf stays in place, cleared
                    // to genesis; On semantics: it annihilates.
                    off[index] = Slot::Deleted;
                    let position = index - base_len;
                    if let Some(slot) = on_map.get_mut(position) {
                        if let Some(index) = *slot {
                            on_committed[index] = None;
                        }
                        *slot = None;
                        annihilated = true;
                    }
                }
            }
            _ => {}
        }
    }

    let off_hashes = expected_hashes(&off);
    let off_root = root_of_hashes(&H, &off_hashes);
    let mut on_slots = on_base;
    on_slots.extend(on_committed.into_iter().flatten().map(Slot::Element));
    let on_hashes = expected_hashes(&on_slots);
    let on_root = root_of_hashes(&H, &on_hashes);
    (off_hashes, off_root, on_hashes, on_root, annihilated)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    /// `Optimise::On ≡ Off` holds **only for logs without annihilated draft
    /// appends** — the `Optimise::On` docs promise a *different committed
    /// shape* otherwise (lower leaf count, shifted indexes). So this property
    /// asserts each strategy against its own documented model, and asserts
    /// the On ≡ Off equality exactly on the annihilation-free restriction.
    #[test]
    fn optimise_modes_match_their_documented_semantics(ops in op_log()) {
        let (off_hashes, off_root, on_hashes, on_root, annihilated) = models(&ops);
        let off_actual = replay(&ops, Optimise::Off);
        prop_assert_eq!(&off_actual.0, &off_hashes, "Optimise::Off committed leaves vs model");
        prop_assert_eq!(off_actual.1, off_root, "Optimise::Off root vs model");

        let on_actual = replay(&ops, Optimise::On);
        prop_assert_eq!(&on_actual.0, &on_hashes, "Optimise::On committed leaves vs model");
        prop_assert_eq!(on_actual.1, on_root, "Optimise::On root vs model");

        if annihilated {
            // The documented divergence: every annihilated draft append
            // shrinks the committed leaf count (a deleted *base* leaf stays
            // in place — only draft appends vanish).
            prop_assert!(
                on_actual.0.len() <= off_actual.0.len(),
                "annihilation may only shrink the committed shape"
            );
        } else {
            prop_assert_eq!(&on_actual, &off_actual, "without annihilation On must equal Off");
        }
    }
}

// --------------------------------------------- property 3: encoding invariants

fn is_hex(text: &str) -> bool {
    text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Decodes a (possibly zero-stripped) hex word into the 32 bytes it encodes.
fn decode_word(text: &str) -> Hash {
    let padded = format!("{text:0>64}");
    let mut bytes = [0_u8; 32];
    for (index, chunk) in padded.as_bytes().chunks(2).enumerate() {
        let text = core::str::from_utf8(chunk).expect("ascii");
        bytes[index] = u8::from_str_radix(text, 16).expect("hex digits");
    }
    Hash::from_bytes(bytes)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    /// No parse function exists for the fixed-width encodings (the codec is
    /// write-only), so the round-trip property is structural: hex words parse
    /// back to the exact hash bytes they encode (the real round trip),
    /// sibling/peak counts match the independent layout anchors (peak
    /// count = popcount, sibling count = the proven node's peak height), and
    /// encoding is deterministic.
    #[test]
    fn encoded_proofs_parse_back_to_their_hashes_and_layout(
        leaf_count in 1..=64_u64,
        leaf_target in 0..64_u64,
    ) {
        let mut mmr = Mmr::<KeccakSolHasher, InMemoryStore>::create(H, InMemoryStore::new(), id())
            .expect("create must succeed");
        let elements: Vec<Vec<u8>> = (0..leaf_count).map(|index| format!("el-{index:04}").into_bytes()).collect();
        mmr.append_batch(&slices(&elements)).expect("batch append");
        let leaf = LeafIndex::new(leaf_target % leaf_count);
        let proof = mmr.proof(leaf).expect("proof");

        // Independent layout anchors.
        assert_eq!(
            proof.peaks.len(),
            usize::try_from(leaf_count.count_ones()).expect("peak counts fit usize"),
            "the peak count is popcount(leaf count)"
        );
        assert_eq!(
            proof.siblings.len(),
            accumulators::utils::mmr::sibling_path(leaf, mmr.size()).len(),
            "the sibling count is the proven node's peak height"
        );

        // Solidity: 0x-prefixed fixed-width words that parse back to the
        // exact bytes.
        let encoded: EncodedProof = FixedWidth::solidity().encode(&proof).expect("encodes");
        assert!(encoded.element_hash.starts_with("0x") && encoded.element_hash.len() == 66);
        assert!(is_hex(&encoded.element_hash[2..]));
        assert_eq!(
            decode_word(&encoded.element_hash[2..]),
            proof.element_hash,
            "the element hash word parses back to the hash"
        );
        assert_eq!(decode_word(&encoded.root[2..]), proof.root);
        for (word, hash) in encoded.siblings.iter().zip(&proof.siblings) {
            assert_eq!(word.len(), 66);
            assert_eq!(decode_word(&word[2..]), *hash);
        }
        // Deterministic: the same proof encodes identically.
        let again: EncodedProof = FixedWidth::solidity().encode(&proof).expect("encodes");
        prop_assert_eq!(encoded, again);

        // Cairo: bare minimal felt hex that parses back to the same bytes.
        let felt: EncodedProof = FixedWidth::cairo().encode(&proof).expect("encodes");
        assert!(!felt.element_hash.starts_with("0x"));
        assert_eq!(decode_word(&felt.element_hash), proof.element_hash);
        assert_eq!(decode_word(&felt.root), proof.root);

        // Multiproofs: refs stay within the pool, leaves stay ascending.
        let subset: Vec<LeafIndex> = (0..leaf_count)
            .filter(|index| index % 3 == 0)
            .map(LeafIndex::new)
            .collect();
        let multi = mmr.multiproof(subset).expect("multiproof");
        let encoded_multi: EncodedMultiProof =
            FixedWidth::solidity().encode_multi(&multi).expect("encodes");
        for reference in &encoded_multi.sibling_refs {
            prop_assert!((*reference as usize) < multi.sibling_pool.len(), "refs index the pool");
        }
        let mut sorted = multi.leaves.clone();
        sorted.sort();
        prop_assert_eq!(multi.leaves, sorted);

        // A preset too small for the peak list is a typed rejection, not a
        // truncation.
        if proof.peaks.len() > 1 {
            let tiny = FixedWidth {
                hash_width: Some(64),
                size_width: None,
                peaks_size: Some(1),
                siblings_size: None,
                style: HexStyle::Word,
            };
            let rejected = tiny.encode(&proof);
            assert!(
                matches!(rejected, Err(accumulators::mmr::EncodingError::ListTooLong { .. })),
                "an over-long list must be a typed rejection"
            );
        }
    }
}

// -------------------------------------------------- property 4: key codec

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    /// `decode(encode(x)) == x` for arbitrary ids, every assigned table tag
    /// and arbitrary subkeys — and decoding arbitrary bytes never panics
    /// (foreign keys are an `Option`, not a crash).
    #[test]
    fn keys_round_trip_and_random_bytes_never_panic(
        id_bytes in any::<[u8; 16]>(),
        tag in 0_u8..=10,
        subkey in any::<u64>(),
        random_bytes in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let id = AccumulatorId::from_bytes(id_bytes);
        let table = Table::from_repr(tag).expect("tags 0..=10 are assigned");
        let key = keys::encode(&id, table, subkey);
        let (decoded_id, decoded_table, decoded_subkey) = keys::decode(&key)
            .expect("encoded keys must decode");
        prop_assert_eq!(decoded_id, id_bytes.to_vec());
        prop_assert_eq!(decoded_table, table);
        prop_assert_eq!(decoded_subkey, subkey);

        // Arbitrary bytes: no panic, an honest Option.
        let _unused = keys::decode(&random_bytes);
    }
}
