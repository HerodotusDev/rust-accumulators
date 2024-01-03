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

mmr.append("1".to_string()).await?;
mmr.append("2".to_string()).await?;
mmr.append("3".to_string()).await?;
let example_value = "4".to_string();
let example_append = mmr
    .append(example_value.clone())
    .await?;

let proof = mmr
    .get_proof(example_append.element_index, None)
    .await?;

assert!(mmr
    .verify_proof(proof, example_value, None)
    .await?)
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
    .await?;

let sub_mmrs = vec![(mmr.elements_count.get().await?, mmr.get_metadata())];

let mut stacked_mmr =
    MMR::new_stacked(store.clone(), hasher.clone(), None, sub_mmrs.clone()).await?;
stacked_mmr
    .append("2".to_string())
    .await?;

let proof = stacked_mmr
    .get_proof(example_append.element_index, None)
    .await?;

assert!(stacked_mmr
    .verify_proof(proof, example_value, None)
    .await?);
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

mmr.append("1".to_string()).await?;
mmr.append("2".to_string()).await?;

let mut draft = mmr.start_draft().await;
draft
    .mmr
    .append("3".to_string())
    .await?;

draft
    .mmr
    .append("4".to_string())
    .await?;

let draft_bag = draft.mmr.bag_the_peaks(None).await?;
let draft_root = draft
    .mmr
    .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get().await?)?;

draft.commit().await?;

let bag = mmr.bag_the_peaks(None).await?;
let root = mmr
    .calculate_root_hash(&bag, mmr.elements_count.get().await?)?;

assert_eq!(draft_root, root);

let mut draft = mmr.start_draft().await?;
draft
    .mmr
    .append("5".to_string())
    .await?;

draft
    .mmr
    .append("6".to_string())
    .await?;

draft.discard();

let after_discard_bag = mmr.bag_the_peaks(None).await?;
let after_discard_root = mmr
    .calculate_root_hash(&after_discard_bag, mmr.elements_count.get().await?)?;

assert_eq!(after_discard_root, root);
```

## Benchmarks

ARM - M1
Insertion, check code [here](https://github.com/HerodotusDev/rust-accumulators/blob/develop/benches/mmr_benchmark.rs)

| N   | speed    |
| --- | -------- |
| 10k | 1.6370 s |
| 1M  | 19.279 s |
