# Merkle Mountain Range

MMR is a structure that allows appending and proving efficiently. Time complexity of both operations is O(log tree_size).

#### Requires: `features = ["mmr"]`

## Basic Example

```rust
use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher, mmr::MMR, store::memory::InMemoryStore,
};

let store = InMemoryStore::default();
let store_rc = Arc::new(store);
let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

let mut mmr = MMR::new(store_rc, hasher, None);

mmr.append("1".to_string()).await.expect("Failed to append");
mmr.append("2".to_string()).await.expect("Failed to append");
mmr.append("3".to_string()).await.expect("Failed to append");
let example_value = "4".to_string();
let example_append = mmr
    .append(example_value.clone())
    .await
    .expect("Failed to append");

let proof = mmr
    .get_proof(example_append.element_index, None)
    .await
    .expect("Failed to get proof");

assert!(mmr
    .verify_proof(proof, example_value, None)
    .await
    .expect("Failed to verify proof"));
```

## MMR Types

### MMR

The regular MMR, see the example above.

#### Requires: `features = ["mmr"]`

### StackedMMR

An infinitely stackable MMR, used to reduce data duplication when handling multiple MMRs, or handling things like Precomputation and DraftMMRs

#### Requires: `features = ["stacked_mmr"]`

#### Example

```rust
use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher, mmr::MMR, store::memory::InMemoryStore,
};

let store = InMemoryStore::new();
let store = Arc::new(store);
let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

let example_value = "1".to_string();
let example_append = mmr
    .append(example_value.clone())
    .await
    .expect("Failed to append");

let sub_mmrs = vec![(mmr.elements_count.get().await, mmr.get_metadata())];

let mut stacked_mmr =
    MMR::new_stacked(store.clone(), hasher.clone(), None, sub_mmrs.clone()).await;
stacked_mmr
    .append("2".to_string())
    .await
    .expect("Failed to append");

let proof = stacked_mmr
    .get_proof(example_append.element_index, None)
    .await
    .expect("Failed to get proof");

assert!(stacked_mmr
    .verify_proof(proof, example_value, None)
    .await
    .unwrap());
```

### DraftMMR

A MMR built on the StackedMMR, that is used for precomputation of the MMR, which then can be either discarded or committed to the MMR it was made from.

#### Requires: `features = ["draft_mmr"]`

#### Example

```rust
use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher, mmr::MMR, store::memory::InMemoryStore,
};

let store = InMemoryStore::new();
let store = Arc::new(store);
let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

mmr.append("1".to_string()).await.expect("Failed to append");
mmr.append("2".to_string()).await.expect("Failed to append");

let mut draft = mmr.start_draft().await;
draft
    .mmr
    .append("3".to_string())
    .await
    .expect("Failed to append");
draft
    .mmr
    .append("4".to_string())
    .await
    .expect("Failed to append");

let draft_bag = draft.mmr.bag_the_peaks(None).await.unwrap();
let draft_root = draft
    .mmr
    .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get().await)
    .expect("Failed to calculate root hash");

draft.commit().await;

let bag = mmr.bag_the_peaks(None).await.unwrap();
let root = mmr
    .calculate_root_hash(&bag, mmr.elements_count.get().await)
    .expect("Failed to calculate root hash");

assert_eq!(draft_root, root);

let mut draft = mmr.start_draft().await;
draft
    .mmr
    .append("5".to_string())
    .await
    .expect("Failed to append");
draft
    .mmr
    .append("6".to_string())
    .await
    .expect("Failed to append");

draft.discard().await;

let after_discard_bag = mmr.bag_the_peaks(None).await.unwrap();
let after_discard_root = mmr
    .calculate_root_hash(&after_discard_bag, mmr.elements_count.get().await)
    .expect("Failed to calculate root hash");

assert_eq!(after_discard_root, root);
```

## Benchmarks

```sh
MMR insertion/times/10000
                        time:   [1.6310 s 1.6370 s 1.6463 s]
MMR insertion/times/100000
                        time:   [19.234 s 19.279 s 19.323 s]
```
