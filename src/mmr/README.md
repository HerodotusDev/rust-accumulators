# Merkle Mountain Range

MMR is a structure that allows appending and proving efficiently. Time complexity of both operations is O(log tree_size).

## Example

```rust
use accumulators::{
    hasher::{stark_poseidon::StarkPoseidonHasher, Hasher},
    mmr::{
        helpers::{AppendResult, Proof, ProofOptions},
        MMR,
    },
    store::sqlite::SQLiteStore,
};

let store = SQLiteStore::new(":memory:").unwrap();
let hasher = StarkPoseidonHasher::new(Some(false));
store.init().expect("Failed to init store");

let mut mmr = MMR::new(store, hasher.clone(), None);

let _ = mmr.append("1".to_string()).unwrap();
let _ = mmr.append("2".to_string()).unwrap();
let _ = mmr.append("3".to_string()).unwrap();
let append_result = mmr.append("4".to_string()).unwrap();

let proof4 = mmr
    .get_proof(append_result.element_index,
    ProofOptions {
            elements_count: None,
            formatting_opts: None,
        },
    )
    .unwrap();

mmr.verify_proof(
    proof4,
    "4".to_string(),
    ProofOptions {
        elements_count: None,
        formatting_opts: None,
    },
)
.unwrap(); //return true
```

### Benchmark

```sh
MMR insertion/times/10000
                        time:   [1.6310 s 1.6370 s 1.6463 s]
MMR insertion/times/100000
                        time:   [19.234 s 19.279 s 19.323 s]
```
