# Rust MMR

```
  _____           _     __  __ __  __ _____
 |  __ \         | |   |  \/  |  \/  |  __ \
 | |__) |   _ ___| |_  | \  / | \  / | |__) |
 |  _  / | | / __| __| | |\/| | |\/| |  _  /
 | | \ \ |_| \__ \ |_  | |  | | |  | | | \ \
 |_|  \_\__,_|___/\__| |_|  |_|_|  |_|_|  \_\

```

## Example

```rust
use std::vec;

use mmr::{
    core::CoreMMR,
    hash::{stark_poseidon::StarkPoseidonHasher, IHasher},
    helpers::AppendResult,
    proof::{Proof, ProofOptions},
    store::sqlite::SQLiteStore,
};

let store = SQLiteStore::new(":memory:").unwrap();
let hasher = StarkPoseidonHasher::new(Some(false));
let _ = store.init();

let mut mmr = CoreMMR::new(store, hasher.clone(), None);

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
    proof2,
    "2".to_string(),
    ProofOptions {
        elements_count: None,
        formatting_opts: None,
    },
)
.unwrap(); //return true
```

## Reference

- [accumulators - CoreMMR](https://github.com/HerodotusDev/accumulators)
