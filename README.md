![](/banner.png)

# Rust Accumulators

[![Cargo Test](https://github.com/HerodotusDev/rust-accumulators/actions/workflows/ci.yml/badge.svg)](https://github.com/HerodotusDev/rust-accumulators/actions/workflows/ci.yml)

Cryptographic accumulators with pluggable storage and hashing. Type-stated
MMRs (plain, stacked, draft, peaks-only; append-only, editable, nullifying),
self-contained proofs and multiproofs, and an incremental Merkle tree.
`no_std`-compatible core; misuse is a compile error wherever possible.

# Quick Start

Add the dependency (the default features are a working out-of-the-box MMR):

```toml
accumulators = { version = "1.0.0-rc.1", features = ["all"] }
```

```rust
use accumulators::hashers::KeccakSolHasher;
use accumulators::ids::AccumulatorId;
use accumulators::mmr::Mmr;
use accumulators::primitives::LeafIndex;
use accumulators::store::memory::InMemoryStore;

let mut mmr: Mmr<KeccakSolHasher, _> = Mmr::create(
    KeccakSolHasher,
    InMemoryStore::new(),
    AccumulatorId::random_v4(),
)
.unwrap();

mmr.append(b"element 0").unwrap();
mmr.append(b"element 1").unwrap();

let proof = mmr.proof(LeafIndex::new(0)).unwrap();
assert!(mmr.verify(&proof, b"element 0").unwrap());
assert!(!mmr.verify(&proof, b"forged").unwrap());
```

# MMR Layout

An MMR of 5 leaves — node indexes above, leaf (element) indexes below.
Merges happen only between equal-height right-spine neighbors, so the
leaf-to-node mapping has gaps (`2i + 1 − popcount(i)`):

```text
height
  2 │                 7  ← peak
  1 │        3                  6
  0 │    1       2       4       5       8  ← peak
        │        │       │       │       │
        L0       L1      L2      L3      L4

peaks = [7, 8]              one peak per set bit of the leaf count
bag   = H(peak_7, peak_8)   peaks bagged right-to-left, leftmost outermost
root  = H(size, bag)        size = node count (here 8)
```

- **node index** — 1-based position in the flat node space (the store-key
  space). Every node, internal or leaf, has one.
- **leaf index** — 0-based position of an appended element. The space all
  *public* proof APIs speak.
- **peak** — root of one perfect subtree; count = `popcount(leaf count)`.
- **bagging** — folding the peaks (right-to-left) with the size into the root.
- **pin size** — the node count a stacked layer is frozen at: reads through a
  pin never exceed it.

# Features

Default: `["mmr", "memory", "keccak_sol", "uuid_v4"]`. `all` enables everything.

| Feature | Adds |
| --- | --- |
| `mmr` | The MMR accumulator: sync `Mmr` / async `AsyncMmr` handles, layout math, self-contained `Proof`/`MultiProof`/`ConsistencyProof` with standalone verification |
| `stacked_mmr` | Stacking on top of the MMR: `pin`/`stack`/`open_stacked` on the sync and async handles, validated sub-views |
| `draft_mmr` | In-memory draft overlays (`Draft` sync, `AsyncDraft` async) with `commit` / `discard` / `commit_as_stacked` and composed-view `consistency_proof` |
| `merkle_tree` | The incremental Merkle tree accumulator (sparse storage, zero-hash ladder) |
| `incremental_merkle_tree` | Compatibility alias of `merkle_tree` |
| `hasher` | Grouping flag for the hasher axis (implied by every hasher feature) |
| `keccak_sol` | Solidity-flavored Keccak-256 hasher (Solidity keccak packing) |
| `poseidon_stark` | Starknet-flavored Poseidon hasher |
| `pedersen_stark` | Starknet-flavored Pedersen hasher |
| `blake2s_stark` | Cairo/Starknet-flavored Blake2s hasher (word-reversed) |
| `store` | The `Store`/`AsyncStore` contract, batches, binary keys, erasure adapters |
| `memory` | In-memory store, concurrent shared-lock reads (std; implies `store`) |
| `heapless` | Fixed-capacity in-memory store, allocation-free inline map (no_std + alloc, works without an allocator; implies `store`) |
| `sqlite` | SQLite store, async-only, atomic transactions (native targets; implies `store`) |
| `sled` | Sled store, atomic `apply_batch` batches, background flusher; async surface offloads to tokio's blocking pool (native targets; implies `store`) |
| `fjall` | Fjall store, atomic write-batch commits over an LSM-tree; async surface offloads to tokio's blocking pool (native targets; implies `store`) |
| `redb` | Redb store, one ACID write transaction per batch, process-crash safe default (`Durability::None`), fsync opt-in per config; async surface offloads to tokio's blocking pool (native targets; implies `store`) |
| `rocksdb` | RocksDB store, one `WriteBatch` per write; async surface offloads to tokio's blocking pool (native targets; implies `store`) |
| `uuid_v4` | Random uuid v4 accumulator ids |
| `uuid_v7` | Time-ordered uuid v7 ids (`now_v7` additionally needs `std`) |
| `ulid` | ULID ids (`generate_ulid` additionally needs `std`) |
| `std` | std-dependent conveniences (implied by the std-backed stores) |
| `serde` | Serde impls for core types (`Hash`, `AccumulatorId`, `NullifierRecord`; `Proof`/`MultiProof`/`ConsistencyProof` under `mmr`) — hex-string hashes, plain-number indexes |

## Accumulators

### - MMR — `features = ["mmr"]`

A Merkle Mountain Range accumulator: sync (`Mmr`) and async (`AsyncMmr`)
handles over one pure state core, batched I/O (an append is one atomic write,
a proof one batched read), self-contained proofs with standalone verification,
stacking/branching (`stacked_mmr`), in-memory drafts with commit/discard
(`draft_mmr`), and shallow/deep nullification. Layout math lives in
`src/mmr/layout.rs` — peak counts, peak heights, path lengths, and
child/parent index algebra are public `const fn`s — and the pure planners
behind the shells (append engine, consistency planning, metadata validation)
are public for custom stores.

### - Incremental Merkle Tree — `features = ["incremental_merkle_tree"]`

An incremental Merkle tree accumulator with sparse storage and a zero-hash
ladder (proofs for every index within capacity). Proofs are self-contained
(each carries its root, so they verify anywhere with just the hasher —
structural tampering is a typed error). The heap-index math (`leaf_heap`,
`heap_level_and_index`) and the pure write/proof planners are public, so a
custom store shell runs the exact code paths of the built-in one.
`src/merkle.rs`.

## Utils

### Hashers:

Hashing functions used for hashing inside accumulators — one trait
(`hashers::Hasher`) to implement your own.

- keccak_sol (Solidity keccak packing): `features = ["keccak_sol"]`
- poseidon_stark: `features = ["poseidon_stark"]`
- pedersen_stark: `features = ["pedersen_stark"]`
- blake2s_stark (Cairo/Starknet-flavored Blake2s): `features = ["blake2s_stark"]`

### Stores:

Key value stores used for storing the accumulator data. Built in: memory,
heapless, sqlite, sled, fjall, redb, and rocksdb — or implement the
`Store`/`AsyncStore` contract (two methods) to plug in your own (postgres,
redis, …).

- memory: `features = ["memory"]`
- heapless (no_std, fixed-capacity): `features = ["heapless"]`
- sqlite: `features = ["sqlite"]`
- sled: `features = ["sled"]`
- fjall: `features = ["fjall"]`
- redb: `features = ["redb"]`
- rocksdb: `features = ["rocksdb"]`

### Ids:

- uuid v4: `features = ["uuid_v4"]`
- uuid v7: `features = ["uuid_v7"]` (constructor additionally needs `std`)
- ulid: `features = ["ulid"]` (constructor additionally needs `std`)
- any custom `Copy` id type via the `ids::TreeId` trait

# Development

MSRV: Rust **1.94** (`rust-version` in `Cargo.toml`).

Test : `cargo test --features all`
Bench : `cargo bench --features all`

Documentation is generated from the source (`cargo doc --features all --open`);
the crate-level docs in `src/lib.rs` and the module docs in `src/mmr/` are the
authoritative API guide.

## Reference

- [accumulators - CoreMMR](https://github.com/HerodotusDev/accumulators)
- [cairo_lib - MMR](https://github.com/HerodotusDev/cairo-lib/tree/main/src/data_structures)

## License

`accumulators` is dual-licensed under the [MIT](./LICENSE-MIT) and
[Apache-2.0](./LICENSE-APACHE) licenses (`MIT OR Apache-2.0`).

---

Herodotus Dev Ltd - 2026
