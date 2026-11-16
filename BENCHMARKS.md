# Benchmarks

Numbers from one full `cargo bench --features all` run of the nine bench
targets (2026-11-16, criterion 0.8.2), saved in `target/criterion/` as the
`1.0.0-rc.1-baseline` baseline. Machine: Apple M3 Pro (12 cores), macOS 26.6.
Sample sizes: 100 per case (30 for the proof legs, 20 for the draft legs);
3 s warm-up. All times are criterion mean point estimates; ± is the
coefficient of variation. Reproduce:

```sh
cargo bench --features all                 # compare against the baseline
cargo bench --features all --bench mmr_benchmark -- --save-baseline <name>
```

Store legs run the identical workload through every backend
(`benches/common/mod.rs`), so the store tables are directly comparable.
Derived per-op numbers (marked `→`) are divisions of the measured means.

## Headline

| | |
|---|---|
| Build an MMR (keccak, memory) | 2.1–2.5 µs/leaf (~430k appends/s) |
| Batched append | 0.59 µs/leaf (~1.7M leaves/s) — **3.7× the naive loop** |
| Verify one proof | 4–6 µs, flat from 1k to 100k leaves |
| Verify cost by backend | identical (~4.7 µs everywhere — verification touches no store) |
| Single proof generation | 2.5–3.2 µs (memory), 4–9 µs (file stores) |
| MMR root | ~1 µs at any size |
| Multiproof, 100 leaves @100k | 178 µs (1.78 µs/leaf, shared sibling pool) |

## Hashers — one `hash_pair` call

| Hasher | time | vs keccak |
|---|---|---|
| blake2s_stark | 98 ns | 0.5× |
| keccak_sol | 184 ns | 1× |
| poseidon_stark | 2.87 µs | 16× |
| pedersen_stark | 14.5 µs | 79× |

Field hashers dominate accumulator cost when used: a poseidon MMR pays
~16× the keccak build time by arithmetic alone.

## MMR (keccak, memory store)

| Leg | 1 000 | 10 000 | 100 000 |
|---|---|---|---|
| build (append loop), total | 1.88 ms | 21.5 ms | 250 ms |
| → per leaf | 1.88 µs | 2.15 µs | 2.50 µs |
| `append_batch`, total | — | 5.85 ms | — |
| → per leaf | — | 0.59 µs | — |
| verify one proof | 4.29 µs | 4.66 µs | 5.67 µs |
| consistency gen / verify | — | 3.5 / 4.6 µs | 4.9 / 5.8 µs |
| root (bag peaks) | — | 0.92 µs | 1.10 µs |

Verification grows ~1.4 µs from 1k to 100k leaves — seventeen extra path
hashes at 184 ns each. That is the entire size dependence.

Proof generation, per proof:

| tree size | individual (`proof`, batch of 10) | multiproof k=10 | k=100 | k=1000 |
|---|---|---|---|---|
| 1 000 | 2.23 µs | 1.20 µs | 0.84 µs | 0.53 µs |
| 10 000 | 2.59 µs | 1.56 µs | 1.26 µs | 1.14 µs |
| 100 000 | 3.19 µs | 2.08 µs | 1.78 µs | 1.87 µs |

The shared sibling pool flattens multiproof cost to ~1.1–2.1 µs per leaf
regardless of k; the payoff over individual proofs grows with k and plateaus
around 1.8× at this stride (evenly spread indexes — clustered sets dedup
better). Shallow nullification records 10 nullifiers on a 100k tree in
2.21 µs (record write only, no restructuring). Hot appending at 100k leaves
sustains 2.81 µs/append.

Drafts (1 000 buffered appends on a 10-leaf base, commit incl.): replay
5.19 ms, `Optimise::On` 5.89 ms — folding costs ~13% on an all-append
workload where there is nothing to fold; it pays when updates/deletes
annihilate. These legs are the noisiest in the suite (CV 16–31%): treat as
indicative only.

## Stacked MMR (3 layers, ~10k leaves, memory)

| Leg | distinct stores | 2+1 mixed | one shared store |
|---|---|---|---|
| hot append (per 500) | 1.31 ms | 1.29 ms | 1.38 ms |
| proof (batch of 10) | 33.7 µs | 33.4 µs | 32.6 µs |
| multiproof k=10 | 23.7 µs | 24.2 µs | 24.3 µs |
| multiproof k=100 | 203 µs | 208 µs | 213 µs |

Stacking is ~free on memory: per-append and per-proof costs match the
single-MMR numbers; layer routing adds no measurable overhead. Shared-store
batching shows no advantage at this scale on memory — it matters on real
storage backends, where it collapses N layer reads into one.

## Store backends — one workload, seven stores

Build = 10 000 appends one at a time; batch = 1 000-leaf `append_batch`;
proof/multiproof/verify at 1 000 leaves (keccak); raw = plain `Store`
read/write of 1 000 keys, no MMR logic. 10k build per-leaf:

| backend | build 10k | →/leaf | batch 1k | →/leaf | proof | multiproof k=100 |
|---|---|---|---|---|---|---|
| memory | **26.1 ms** ⚠ | **2.61 µs** | 858 µs ⚠ | 0.86 µs | **2.48 µs** | **128 µs** |
| heapless | 27.7 ms | 2.77 µs | 756 µs | 0.76 µs | 3.83 µs | 224 µs |
| sled | 38.4 ms | 3.84 µs | 1.14 ms | 1.14 µs | 8.20 µs ⚠ | 510 µs |
| fjall | 57.5 ms ⚠ | 5.75 µs | 1.43 ms ⚠ | 1.43 µs | 6.45 µs | 475 µs |
| rocksdb | 57.9 ms | 5.79 µs | **747 µs** | **0.75 µs** | 9.27 µs | 674 µs |
| redb | 149 ms | 14.9 µs | 3.69 ms ⚠ | 3.69 µs | 4.25 µs | 282 µs |
| sqlite | 568 ms | 56.8 µs | 2.06 ms | 2.06 µs | 48.6 µs | 2.00 ms |

Raw store latency (1 000 keys, no accumulator work):

| backend | read | write |
|---|---|---|
| memory | **36 µs** | **61 µs** |
| heapless | 76 µs | 75 µs |
| redb | 127 µs | 276 µs |
| fjall | 294 µs | 717 µs ⚠ |
| rocksdb | 379 µs | 497 µs ⚠ |
| sled | 431 µs ⚠ | 332 µs |
| sqlite | 1.59 ms | 820 µs |

Verification is store-free and lands at 4.65–4.70 µs on every backend
(multiproof verify k=100: 276–282 µs everywhere). Backend choice changes
write and read latency only.

⚠ = CV above 10% in this run (memory 75–150% on the build/batch legs,
fjall 23–30%, redb batch 63%, sled proof 13%) — allocator and filesystem
noise. Rankings that depend on ⚠ cells are indicative; the clean cells
(heapless, rocksdb, redb read, sqlite, memory raw ops) are solid.

Reads vs writes split the file engines: redb reads fastest (127 µs) but
writes slowest (3.7 ms batch); rocksdb is the reverse (best batch write,
mid reads). sqlite is transaction/commit-bound — the only backend where
batching (2.06 µs/leaf) beats the append loop (56.8 µs/leaf) by 27×.

## Async MMR over sqlite

| Leg | time |
|---|---|
| batched build, 10k leaves | 22.4 ms (2.24 µs/leaf) |
| proof gen (batch of 10) @1k / @10k | 37.9 / 46.2 µs |
| stacked 3-layer, one sqlite: build-append 10k | 23.6 ms |
| stacked: reopen (`open_stacked`) | 1.87 ms |
| stacked: hot appends | 29.1 ms |
| stacked: multiproof k=1 / k=10 / k=100 | 43 / 242 µs / 1.85 ms |

The async shell (tokio + `spawn_blocking` off the file engines) adds no
measurable cost over the sync sqlite numbers; multiproof reads fan out
across layers via `join_ordered`.

## Incremental Merkle Tree (memory, keccak)

| Leg | time |
|---|---|
| initialize (zero ladder) depth 8 / 12 / 16 / 20 | 1.86 / 2.59 / 3.33 / 4.18 µs |
| `set_leaf`, 16 384-capacity tree | 54.1 µs |
| inclusion proof @16k | 12.9 µs |
| verify one proof @16k | 2.81 µs |
| multiproof k=100, depth 12 / 16 / 20 | 47.9 / 84.4 / 111 µs |
| verify multiproof k=100, depth 12 / 16 / 20 | 138 / 213 / 290 µs |

Costs scale with depth, not occupancy — the zero-hash ladder lets unoccupied
regions prove without reads.

## Notes

- Only the top-of-funnel legs are noisier than CV 10%; verify/multiproof
  legs sit at CV ≤ 2% and are the best regression canaries.
- Builds isolate each iteration in a fresh keyspace (fresh
  `AccumulatorId`), so no backend gets a warm-cache advantage.
- The v0.5 numbers are not comparable: the hashing pipeline changed from
  hex strings to bytes in 1.0.0-rc.1.
