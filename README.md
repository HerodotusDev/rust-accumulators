# Rust Accumulators

[![Cargo Test](https://github.com/HerodotusDev/rust-mmr/actions/workflows/ci.yml/badge.svg)](https://github.com/HerodotusDev/rust-mmr/actions/workflows/ci.yml)

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

## Reference

- [accumulators - CoreMMR](https://github.com/HerodotusDev/accumulators)
- [cairo_lib - MMR](https://github.com/HerodotusDev/cairo-lib/tree/main/src/data_structures)

## License

`accumulators` is licensed under the [GNU General Public License v3.0](./LICENSE).

---

Herodotus Dev Ltd - 2023
