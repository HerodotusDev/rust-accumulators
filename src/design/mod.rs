//! Draft API for the 1.0.0-rc.1 redesign — **types only, no implementations yet**.
//!
//! This module is the iteration ground for the new API surface. Everything in
//! here is a trait / struct / enum skeleton with `todo!()` bodies: it exists so
//! we can compile-check ergonomics and misuse-resistance before any algorithm
//! work starts. The existing `mmr` / `merkle_tree` / `store` / `hasher` modules
//! remain the working implementation until this design replaces them.
//!
//! # Design goals (from the owner, verbatim intent)
//!
//! 1. **async and sync** — both must work, including `no_std` environments.
//! 2. **Idiomatic, zero-cost Rust** — newtypes instead of bare `usize`/`String`,
//!    static dispatch instead of `Arc<dyn>`, and APIs that make misuse a
//!    *compile error*, not a runtime surprise.
//! 3. **Light, efficient, performant** — batch reads / batch writes, cached
//!    peaks so appends and roots never round-trip the store.
//! 4. **Modular and user-extensible** — custom hashers, custom stores (rocksdb,
//!    redb, fjall, postgres, …), feature-flagged IDs (uuid v4/v7, ulid, custom).
//! 5. **MMR is the centerpiece** — plain, stacked/branched, draft, and
//!    peaks-only variants with first-class proofs and multiproofs.
//!
//! # Module map
//!
//! | Module                | Contents                                                      |
//! |-----------------------|---------------------------------------------------------------|
//! | [`primitives`](crate::design::primitives)        | `Hash`, `NodeIndex`, `LeafIndex`, `LeafCount`, `MmrSize`, pure layout math |
//! | [`hashers`](crate::design::hashers)           | `Hasher` trait, built-in hashers, `HasherId`                   |
//! | [`store`]             | `Storage` (error axis) + `Store` (sync) / `AsyncStore`, `Batch`, `Retrievable`, erasure adapters, binary key + value wire spec |
//! | [`ids`](crate::design::ids)               | `MmrId` — uuid v4/v7, ulid, custom 16-byte ids                 |
//! | [`mmr`]               | `Mmr` (type-stated kind × mode), `AsyncMmr`, proofs, stacked, draft, nullifiers |
//! | [`merkle`](crate::design::merkle)            | incremental Merkle tree redesign                               |
//!
//! # The four MMR states (owner's model)
//!
//! - **Plain** — built from scratch, full history provable.
//! - **Stacked** — built on top of pinned views of other MMRs; sub-MMRs keep
//!   growing independently, the stack only reads them up to the pin size.
//!   Unlimited depth and breadth; sub-MMRs may live in different stores; one
//!   hasher across all layers.
//! - **Draft** — in-memory overlay on top of any MMR: append, prove, inspect;
//!   then `commit`, `discard`, or `commit_as_stacked`.
//! - **Peaks-only** — created from peaks; root identical to the full MMR, but
//!   only leaves appended on top are provable. Encoded as the [`WithPeaks`](crate::design::mmr::WithPeaks)
//!   type-state so the restriction is visible in the type.
//!
//! # Mutability modes (second type-state axis)
//!
//! `Mmr<H, S, K, M>` — mode `M` says what may happen to leaves after they
//! exist, and is persisted in metadata + validated on `open`:
//!
//! - [`AppendOnly`](crate::design::mmr::AppendOnly) (default) — no `update`/`delete` exists on the type;
//!   mutating history is a compile error.
//! - [`Editable`](crate::design::mmr::Editable) — in-place `update`/`delete` with recomputed paths.
//!   **Base-use only**: available for `Plain` (all leaves) and `WithPeaks`
//!   (only above the seed); an editable MMR cannot be pinned or stacked
//!   upon, and the `Stacked` kind cannot be editable — all compile-time
//!   ([`Stackable`](crate::design::mmr::Stackable)). Stacked accumulators mutate only through
//!   nullifiers.
//! - [`Nullifying`](crate::design::mmr::Nullifying) — data stays append-only forever; `nullify` records
//!   `(mmr id, leaf id) → size at nullification` in a plain table (the same
//!   shape as the on-chain map — no SMT, no cryptographic commitment),
//!   `replace` = nullify + append. Works for all kinds; proofs refuse leaves
//!   with a *resolving* nullifier. Two depths:
//!   - **Shallow** — record holds the size; through a stack, sub-MMR records
//!     count only when their size ≤ the stack point (later history is
//!     invisible through the pin). Available for every kind, any index below
//!     the leaf count (including below a WithPeaks floor).
//!   - **Deep** — record holds `0` ("always applies"); every stacked MMR on
//!     top is influenced regardless of when the nullification happened.
//!     Available for Plain and Stacked only — `WithPeaks` cannot
//!     deep-nullify (compile-time, [`DeepNullifiable`](crate::design::mmr::DeepNullifiable)).
//!   Shallow records live in the topmost MMR's store; deep records in the
//!   store of the layer that holds the value.
//!
//! # Key design decisions (and why)
//!
//! - **`Hash` is `[u8; 32]` behind a newtype.** Every hash in the current code
//!   is a hex `String`, which costs a parse + format per hash operation and
//!   makes equality/hashing semantics accidental. Fixed-width bytes are
//!   `Copy`, zero-cost, `no_std`-safe, and make store values binary.
//! - **Index spaces are distinct types.** The single largest misuse hazard
//!   today is node-index vs leaf-index confusion (`get_proof` takes a node
//!   index, appends return node indexes, nothing distinguishes them). In this
//!   design public APIs take [`LeafIndex`](crate::design::primitives::LeafIndex); [`NodeIndex`](crate::design::primitives::NodeIndex)
//!   only crosses module boundaries internally. Converting between them is an
//!   explicit, named call.
//! - **Peaks are cached in the MMR handle.** Appends only need the current
//!   peaks (bounded by popcount), roots are recomputed from cache, and proofs
//!   need one batched read of the sibling path. The current code does ~11+
//!   store round trips per append; the new one does exactly **one batched
//!   write** per append (and one per *batch* of appends with `append_batch`).
//! - **`Store` is minimal: `read(keys)` + `write(batch)`.** Counters, tables,
//!   routing fn-pointers, and the `InStoreTable`/`InStoreCounter` split all
//!   disappear — the MMR owns its state and talks to the store through two
//!   methods. This is the smallest surface a rocksdb/redb/fjall/postgres
//!   backend needs to implement, and `write` is documented as **atomic** so
//!   draft commits are crash-safe.
//! - **Hasher inputs are split by trust.** `hash_nodes(&[Hash])` is infallible
//!   (inputs are already validated hashes by construction); `hash_leaf(&[u8])`
//!   is fallible because raw elements can be malformed (fixes the Poseidon
//!   `unwrap_or_default`-to-zero bug class). No strings, no hex in the trait.
//! - **Sync core, async shell.** All MMR math lives in pure, sync, `no_std`
//!   functions over cached state ([`state`](crate::design::mmr::state)). `Mmr` (sync store) and
//!   `AsyncMmr` (async store) are thin shells that fetch/commit state; neither
//!   duplicates the algorithms.
//! - **Keys are length-prefixed bytes.** `{mmr_id}:{table}:{index}` colon
//!   parsing is gone; ids cannot collide with delimiters, and key decoding is
//!   total (no `CouldNotDecodeStoreKey`).
//! - **Proofs are self-contained.** A `Proof` carries its own peaks and root,
//!   so verification is standalone (`verify_proof(hasher, &proof, element)`)
//!   — fixing the current bug where verification re-reads peaks from *whatever*
//!   store the verifier points at.
//!
//! # Decisions (resolved with the owner)
//!
//! - **Ids**: generic `Id: TreeId` parameter, `Id = MmrId` default, `Copy`-only.
//! - **Hasher output**: associated `type Output: HashValue` — any `Copy`
//!   byte type works, built-ins stay `Hash` ([u8; 32]).
//! - **Hasher arity**: `hash_pair(a, b)` only — the MMR combines pairs
//!   exclusively; the arity-error class is deleted.
//! - **Store atomicity**: hard requirement on `write`, documented in the
//!   trait docs.
//! - **Proof encodings**: binary core proofs; the [`encoding`](crate::design::mmr::proof::encoding)
//!   module holds the user-extension point `ProofEncoding` and the built-in
//!   `FixedWidth` (v0.5 `FormattingOptions` semantics, extracted:
//!   pad-to-length lists, zero-hash placeholder, `ListTooLong`) with
//!   `solidity()` / `cairo()` presets.
//! - **Errors, unified**: [`crate::design::store::Storage`] is a supertrait
//!   of both `Store` and `AsyncStore` and carries `type Error`; every
//!   accumulator error enum (`MmrError`, `TreeError`, `StackingError`) is
//!   generic over `Storage`, so sync and async shells share one error enum —
//!   no wrappers, no duplication (the `AsyncWrap` draft hack is gone). All
//!   enums are `thiserror`, `#[non_exhaustive]`, with `#[source]` chaining
//!   (deliberately not `#[from]` for backend errors — see the `Storage`
//!   docs). Error payloads carry **typed** indexes (`LeafIndex`/`MmrSize`),
//!   never raw `u64`. `Corrupted` is exhaustive over malformed persisted
//!   records (missing/malformed/hasher/peaks/root/mode).
//! - **Compile-time grid, closed**: the kinds × modes grid is enforced
//!   structurally — `EditableKind` (Plain, WithPeaks) gates `update`/`delete`
//!   so Stacked×Editable is unconstructible, `DeepNullifiable` (Plain,
//!   Stacked) gates `nullify_deep`/`replace_deep` on **all three surfaces**
//!   (handle, async shell, draft), `Stackable` gates `pin`/`stack`/
//!   `commit_as_stacked`. The async shell mirrors the sync surface fully
//!   (constructors, accessors, `verify`, `leaf_hash`; pure checks like
//!   `verify`/`root` stay sync even there).
//! - **Loose inputs, typed outputs**: batch APIs take `IntoIterator<Item:
//!   AsRef<[u8]>>` / `IntoIterator<Item = LeafIndex>` (any caller shape, no
//!   collects); `Batch` ops use `Cow<'a, [u8]>` (borrowed hot path, owned
//!   runtime-built keys); `Hasher::config` returns `Cow<'static, str>`
//!   (built-ins borrow literals, custom hashers own runtime configs);
//!   per-mode named constructors (`create_editable`, `open_nullifying`, …)
//!   spare users the turbofish. Batch/checker writes stay `write(batch)`.
//! - **Falling is structural, not conventional**: hashing beyond leaf
//!   ingestion is infallible — `bag_peaks`, `root`, `apply_append[_batch]`,
//!   `ZeroLadder::new` return plain values (the `hash_pair`-only trait makes
//!   the whole merge/bag error class impossible, not just unlikely). A draft
//!   `commit` failure returns the draft (and its log) in [`CommitFailure`](crate::design::mmr::CommitFailure)
//!   — the safe action (discard) is never lost to a failed store write.
//!   `NullifierSet::nullify_shallow` rejects size `0` (the wire format's
//!   deep marker) with [`NullifierError::ZeroShallowSize`](crate::design::mmr::NullifierError::ZeroShallowSize).
//! - **Persisted formats, specified**: the full wire spec (keys, value
//!   encodings, `Subviews` record, `TreeNode` heap-index subkey, hasher/mode
//!   records) lives in [`keys`](crate::design::store::keys) module docs — big-endian everywhere,
//!   canonical `HashValue` bytes, `u16`-length text records.
//! - **Editable `delete`**: in-place null write, dense structure, no
//!   compaction.
//! - **Nullifiers**: plain record map in the store (no SMT, no commitment);
//!   shallow + deep depths (deep unconstructible on WithPeaks);
//!   nullification works for any index below the leaf count (including
//!   below a WithPeaks floor — records are index-keyed, no content needed);
//!   drafts buffer nullifications and commit them as batches.
//! - **Editable × stacking**: strictly separated. Editable MMRs are base-use
//!   only (Plain / WithPeaks); `pin`, `stack`, and draft `commit_as_stacked`
//!   exist only for `Stackable` modes (AppendOnly, Nullifying). The branched
//!   -parent runtime guard is unnecessary — the misuse is unconstructible.
//! - **Drafts**: full op-log overlay — a draft offers exactly the operations
//!   of its base's mode, buffers everything in order, and commit replays
//!   into the base (or as a new stacked layer for Stackable modes).
//!   `Optimise::Off` (default) replays every action; `Optimise::On` folds
//!   each leaf's sequence to its net effect — including skipping both the
//!   append and the record when an in-draft append is later nullified
//!   (nullifications of pre-existing leaves always apply).
//! - **Store retrieval & identity**: [`crate::design::store::Retrievable`]
//!   stores persist a canonical locator, so a stacked MMR can be reopened
//!   ([`crate::design::mmr::stacked::open_stacked`]) and locator equality
//!   identifies shared stores for cross-layer batch coalescing.
//! - **Erasure**: [`crate::design::store::ErasedStore`] /
//!   [`crate::design::store::ErasedAsyncStore`] opt-in dyn adapters for
//!   mixed-type stacks (every layer wrapped; session-local only).
//!
//! # Open questions (do not resolve silently)
//!
//! No blocking questions remain. The draft passed a four-angle pre-
//! implementation review (API ergonomics, misuse-resistance, no_std/async/
//! wasm/features, errors + idiomatic Rust); every blocker it found is
//! resolved in the draft. Implementation-stage items tracked here:
//!
//! - async drafts — [`Mmr::start_draft`](crate::design::mmr::Mmr::start_draft) exists on the sync shell; the async
//!   shell needs either an async draft (same overlay, commit via
//!   [`crate::design::store::AsyncStore`]) or a documented sync-only draft
//!   (see [`async_mmr`](crate::design::mmr::async_mmr));
//! - CI jobs for `--target wasm32-unknown-unknown` (with
//!   `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'`) and a `no_std` target
//!   check — the wasm build passes locally but nothing pins it;
//! - the `#![no_std]` flip: design code is no_std-clean (verified),
//!   `thiserror` is already `default-features = false`; the flip itself is
//!   part of the 1.0.0-rc.1 swap (v0.5 modules are std-bound);

// Draft status: bodies are `todo!()` placeholders, so most fields and helper
// methods are intentionally unread/unreachable for now, constructors
// intentionally take ownership of hasher/store, and impl lifetimes become
// load-bearing once bodies land — clippy cannot see that through `todo!()`.
// All allowances are scoped here and removed as implementations arrive.
#![allow(dead_code)]
#![allow(clippy::needless_pass_by_value, clippy::elidable_lifetime_names)]

pub mod ids;
pub mod merkle;
pub mod mmr;
pub mod primitives;
pub mod store;

/// Hashing abstractions.
pub mod hashers;
