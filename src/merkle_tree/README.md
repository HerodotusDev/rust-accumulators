# Incremental Merkle Tree

Incremental Merkle Tree is a structure that contains a constant amount of hashes, allows updating a given hash and proving efficiently. Time complexity of both operations is O(log tree_size).

#### Requires: `features = ["incremental_merkle_tree"]`

## Example

```rust
use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher,
    merkle_tree::incremental::IncrementalMerkleTree, store::memory::InMemoryStore,
};

let store = InMemoryStore::new();
let store = Arc::new(store);
let hasher = StarkPoseidonHasher::new(Some(false));

let tree = IncrementalMerkleTree::initialize(16, "0x0".to_string(), hasher, store, None).await?;

let path = tree.get_inclusion_proof(10).await?;
let valid_proof = tree.verify_proof(10, "0x0", &path).await?;
assert!(valid_proof);

let invalid_proof = tree.verify_proof(10, "0x1", &path).await?;
assert!(!invalid_proof);
```

### Benchmark

ARM - M1
Insertion, check code [here](https://github.com/HerodotusDev/rust-accumulators/blob/develop/benches/incremental_benchmark.rs)

| N   | speed     |
| --- | --------- |
| 10k | 321.26 ms |
| 1M  | 35.413 s  |
