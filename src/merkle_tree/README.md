# Incremental Merkle Tree

Incremental Merkle Tree is a structure that contains a constant amount of hashes, allows updating a given hash and proving efficiently. Time complexity of both operations is O(log tree_size).

## Example

```rust
    use accumulators::{
        hasher::stark_poseidon::StarkPoseidonHasher, merkle_tree::incremental::IncrementalMerkleTree,
        store::sqlite::SQLiteStore,
    };
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    store.init().expect("Failed to init store");
    let tree = IncrementalMerkleTree::initialize(16, "0x0".to_string(), hasher, store, None);

    let path = tree.get_inclusion_proof(10).unwrap();
    let valid_proof = tree.verify_proof(10, "0x0", &path).unwrap();
    assert_eq!(valid_proof, true);

    let invalid_proof = tree.verify_proof(10, "0x1", &path).unwrap();
    assert_eq!(invalid_proof, false);
```

### Benchmark

```sh
Incremental Merkle Tree insertion/times/10000
                        time:   [154.39 ms 154.89 ms 155.38 ms]
Incremental Merkle Tree insertion/times/1000000
                        time:   [17.946 s 18.027 s 18.125 s]
```
