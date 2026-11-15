# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-rc.1] - Unreleased

A ground-up rewrite of the accumulator library. The public API, the on-disk
layout, and the hashing pipeline all changed; nothing from the 0.5.x series
carries over, and persisted v0.5 data is not migratable.

### Added

- Type-state accumulators: kinds (`Plain`, `WithPeaks`, `Stacked`) and modes
  (`AppendOnly`, `Editable`, `Nullifying`) are part of the handle type, so an
  illegal operation for a configuration is a compile error instead of a
  runtime refusal.
- Kind × mode type aliases for every valid handle combination
  (`PlainAppendMmr`, `PlainEditableMmr`, `PlainNullifyingMmr`,
  `WithPeaksAppendMmr`, `WithPeaksEditableMmr`, `WithPeaksNullifyingMmr`,
  `StackedAppendMmr`, `StackedNullifyingMmr`, and the `Async`-prefixed twins),
  each with the id parameter defaulting to `AccumulatorId`.
- Named `open_stacked_append_only` / `open_stacked_nullifying` variants of
  `open_stacked`, avoiding the four-parameter turbofish; the generic
  `open_stacked` remains for exotic ids and stackable modes.
- Sync `Mmr` and async `AsyncMmr` handles over one shared pure state core;
  the two shells differ only in how they fetch and commit, with one generic
  error enum.
- Self-contained `Proof` and `MultiProof`: each carries its own peaks, root,
  and size, so verification needs only the proof and a trusted root — no
  store, no shared state with the producer. `verify_proof_hashed` accepts
  pre-hashed elements.
- Consistency proofs (Reyzin–Yakoubov): `consistency_proof(prev_size)` on the
  sync and async handles produces a self-contained `ConsistencyProof` — the
  earlier MMR's peaks plus one canonical bridge list — and the standalone
  `verify_consistency_proof(hasher, proof, prev_root, root)` confirms the
  prefix relationship from the two roots alone. Typed
  `ProofInconsistency` errors, serde impls, and an exhaustive test suite
  (every prefix pair up to 600 leaves, 183,015 pairs, against a brute-force
  reference) are included.
- Nullification as a first-class axis: dual-depth nullifier sets with shallow
  records that deepen in place. Records only ever strengthen, nullifiers
  compose through stacked layers, and nullifier resolution is batched — one
  read per distinct store, not per leaf.
- Stacked accumulators (`stacked_mmr`): `stack`/`pin`/`open_stacked` build
  sub-MMRs on top of an existing one, with the pin boundary acting as a
  provenance floor — records and appends written after a pin are invisible
  below it. Sub-views are validated on open (`InvalidSubViews`), pinned
  stacks flatten into multi-layer views so pinned stacks compose, and stacked
  I/O is one batched call per distinct store.
- Drafts (`draft_mmr`): in-memory overlays over any handle with
  `commit` / `discard` / `commit_as_stacked`. Commits are atomic batched
  writes per store target and consecutive buffered appends coalesce into one
  append batch. The draft op-log is property-tested against a reference model.
- An incremental Merkle tree accumulator (`merkle_tree`): fixed capacity
  `2^depth`, sparse storage, and a zero-hash ladder so every index within
  capacity has a proof. Metadata (root, depth) persists across reopen.
- `no_std` support: the core runs on `alloc` alone and compiles for
  `wasm32-unknown-unknown` and `thumbv7em-none-eabihf`. Store backends are
  `std` consumers behind features — except `heapless`, whose fixed-capacity
  map stays allocation-free.
- A `heapless` store backend (`heapless` feature): a fixed-capacity,
  const-generic key-value store whose map lives inline with no allocator —
  the embedded/MCU backend, valid on `thumbv7em` and `wasm`. Typed
  capacity (`Full`) and key/value-cap errors, all-or-nothing batch writes
  under one critical section, and independent deep-copy clones.
- A batching contract, enforced by conformance tests: an append is one atomic
  batch write (a batch of appends is one write total), a proof is one batched
  read, and draft commits and stacked I/O are one batched call per distinct
  store. Store writes are atomic by contract — partial application would
  corrupt accumulators, so it is a hard requirement on every backend.
- A binary key layout: length-prefixed binary keys replace v0.5's
  colon-joined strings, with the 255-byte accumulator-id bound asserted at
  encode time so cross-accumulator keyspace collisions fail fast.
- A pluggable store contract: two methods (`read`/`write` batches) on
  `Store`/`AsyncStore`, with an optional capability layer (`same_store`,
  `identity`, `locator`) whose defaults are always correct. A store
  conformance test suite pins the contract.
- Four durable embedded store backends, each mapping the atomic-write
  contract onto its native primitive:
  - sled — atomic `apply_batch` batches over an epoch-based LSM store.
  - fjall — atomic write batches across the database's keyspaces.
  - redb — one ACID write transaction per batch; process-crash safe by
    default (`Durability::None`), power-loss fsync opt-in per config.
  - rocksdb — one `WriteBatch` per write, WAL-backed with per-batch
    recovery.
- Hashers behind one `Hasher` trait — KeccakSol (Solidity keccak packing),
  PoseidonStark, PedersenStark, and Cairo-flavored
  Blake2s — or implement your own. Hashing is pairs-only: `hash_pair` is
  infallible, so bagging, roots, and appends are infallible too; `Result`
  exists only where untrusted input arrives (`hash_leaf`). Stark field
  hashers output `Felt`, so out-of-range values are rejected by checked
  conversion rather than wrapping silently.
- Wire encodings for foreign verifiers: `solidity()` (0x-prefixed canonical
  words) and `cairo()` (bare felt hex) presets, pinned by golden tests.
- A `serde` feature: hex-string hashes and ids, plain-number indexes, and
  impls for proofs, multiproofs, consistency proofs, and nullifier records,
  plus a `HexHash` adapter for foreign hash outputs.
- Ids: uuid v4, uuid v7, ULID, or any `Copy` type via the `TreeId` trait.
  Time-based constructors (`now_v7`, `generate_ulid`) require `std`.
- MSRV 1.94 (edition 2024). CI runs MSRV (`cargo hack check --rust-version`),
  each-feature, and semver-checks jobs plus a weekly maintenance workflow.

### Changed

- **Breaking:** the hashing pipeline moved from hex strings to raw bytes end
  to end. Hash outputs (`Hash` is `[u8; 32]` behind a newtype), keys, and
  persisted records are all binary now. Roots and proofs computed by 1.0.0
  do not match v0.5 values for the same elements, and accumulators written
  by 0.5.x do not reopen — re-baseline any persisted data and benchmarks.
- **Breaking:** the API surface is new. `MMR` is replaced by the sync `Mmr`
  and async `AsyncMmr` handles; `get_proof`/`get_proofs` by
  `proof`/`multiproof`; the store-dependent `verify_proof` by standalone
  `verify_proof`/`verify_multi_proof`; `MmrId` by `AccumulatorId`; the async-only v0.5
  core by the sync core with an async shell. Appends take `&[u8]`, not
  `String`.
- **Breaking:** the store trait is binary and batched. v0.5's `get`/`set` over
  `String` keys and values is replaced by `read(&[&[u8]])` /
  `write(Batch)` over `Vec<u8>`. Store data written by v0.5 backends cannot
  be migrated; start from an empty store.
- **Breaking:** the file-backed store configs (sled, redb, rocksdb, fjall)
  share one idiom: private fields, `with_*` consuming chain setters,
  `Store::open(config)` as the canonical entry, and `Store::open_path(path)`
  as the all-defaults shortcut. `SledConfig::open` and `RedbConfig::open`
  are gone (open through `SledStore`/`RedbStore`), redb and fjall config
  fields are private, and the bare-named sled and rocksdb setters gained the
  `with_` prefix.
- **Breaking:** `SubView::single` takes `(id, store, pinned_size)` and
  derives the layer locator from `Store::locator` — the same semantics as
  `Mmr::pin` (`None` for session-local backends). Hand-pinned locators go
  through the new `SubView::with_locator`.
- **Breaking:** the license changed from GPL-3.0-only to the dual
  `MIT OR Apache-2.0`.
- Formatting is no longer the core's job. v0.5's `get_proofs` rendering is
  replaced by the wire-encoding presets above.
- Accumulator configuration is persisted: hasher identity and its config are
  stored in metadata, so opening an accumulator with a mismatched hasher or
  pad configuration is rejected instead of silently hashing with the wrong
  parameters. WithPeaks
  provenance is likewise persisted and its floor restored on open.
- The SQLite store implements `AsyncStore` only (sqlx is async); a sync `Mmr`
  over SQLite is unconstructible at compile time.
- The SQLite store runs in WAL journal mode with `synchronous=NORMAL` —
  consistent after a process crash without an fsync per commit — and chunks
  multi-row deletes into bounded statements to stay under SQLite's
  per-statement variable limit.
- The memory store serves reads under a shared lock, so concurrent readers
  no longer serialize behind writers, and it prunes dead entries from its
  shared-store registry when a new named store is registered.
- The Pedersen genesis is `pedersen(seed, 0)` — v0.5's genesis was
  unreachable (its seed string was not valid hex).

### Removed

- The hex-string pipeline and everything built on it: hex-parsed hashes,
  string store keys, and the v0.5 `Store`/`AsyncStore` trait signatures.
- The `get_proofs` formatting API.
- `SubKey` and its eq/hash disagreement — gone with the binary keyspace.
- Public MMR state fields. State is private behind read accessors
  (`leaf_count`/`node_count`/`peaks`/`provenance`), so external code can no
  longer forge divergent state.
- The old hasher feature and module names, renamed to make the output type
  explicit. Migration table:

  | v0.5 name                     | 1.0 name                        |
  |-------------------------------|---------------------------------|
  | feature `keccak`              | feature `keccak_sol`            |
  | feature `poseidon`            | feature `poseidon_stark`        |
  | feature `pedersen`            | feature `pedersen_stark`        |
  | feature `blake`               | feature `blake2s_stark`         |
  | module `hashers::keccak`      | module `hashers::keccak_sol`    |
  | module `hashers::blake2s`     | module `hashers::blake2s_stark` |
  | module `hashers::stark_pedersen` | module `hashers::pedersen_stark` |
  | module `hashers::stark_poseidon` | module `hashers::poseidon_stark` |

### Fixed

- Proof sets for non-power-of-two leaf counts: the tree's zero-hash ladder
  resolves virtual siblings correctly, where v0.5's proofs for such sets were
  wrong.
- The incremental tree never updated its cached root on writes (`root()`
  always returned the empty-tree root and multiproof verification always
  failed after the first write), and `open` discarded the persisted root.
- Tree multiproofs resolved ladder levels from the root instead of from the
  leaf, corrupting every multiproof that needed a virtual sibling.
- Errors are no longer swallowed: malformed and absent records are a typed
  `MalformedRecord`/`MissingRecord` distinction everywhere, including
  nullifier records and the tree.
- Draft commit is atomic: one batched write per store target, instead of a
  commit sequence that could leave partial state on failure.
- `stack` panicked for any non-empty pin (peaks were routed before the
  sub-views were installed).
- Multiproofs no longer accept truncated element lists: an element-count
  mismatch is rejected (`ElementCountMismatch`) instead of silently verifying
  against a shorter set.
- Stacked nullifier resolution iterates every layer whose pin covers the
  node — records were previously invisible past the owner layer.
- `LeafIndex` overflow silently fell back to a wrong value; indices beyond
  `MAX_LEAF_COUNT` are now rejected.
- The Blake2s genesis is re-pinned through `hash_leaf(seed)`, restoring the
  `genesis == hash_leaf(seed)` invariant across all four hashers.
- SQLite `:memory:` databases were unusable through the connection pool
  (each pooled connection owned a private database); such pools now pin
  `max_connections(1)`.

### Security

- `unsafe` is forbidden crate-wide (`unsafe_code = "forbid"`), and the full
  lint table (clippy pedantic, `unwrap_used`/`expect_used`, missing docs,
  rustdoc all) is enforced at `-D warnings` in CI.
- Proof verification is total: a fabricated or malformed proof can at worst
  verify to `false` — it never panics and never falsely passes. Multiproof
  truncation false-accepts are rejected (`ElementCountMismatch`).
- The keyspace is collision-safe across accumulators: the 255-byte id bound
  is asserted at key-encode time rather than trusting unbounded ids.

[1.0.0]: https://github.com/HerodotusDev/rust-accumulators/compare/0.5.1...HEAD
