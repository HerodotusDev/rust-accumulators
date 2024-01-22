![](/banner.png)

# Rust Accumulators

[![Cargo Test](https://github.com/HerodotusDev/rust-mmr/actions/workflows/ci.yml/badge.svg)](https://github.com/HerodotusDev/rust-mmr/actions/workflows/ci.yml)

# Quick Start

Add dependency on `Cargo.toml`

# Development

Test : `cargo test --all-features`
Bench : `cargo bench --all-features`

```rust
accumulators = { version = "0.4.0", features = ["all"] }
```

## Accumulators

### - [MMR](./src/mmr/README.md)

#### Requires: `features = ["mmr"]`

A Rust implementation of a Merkle Mountain Range (MMR) accumulator. With extensions.

[MMR's README.md](./src/mmr/README.md)

### - [Incremental Merkle Tree](./src/merkle_tree/README.md)

#### Requires: `features = ["incremental_merkle_tree"]`

A Rust implementation of an Incremental Merkle Tree accumulator.

[Incremental Merkle Tree's README.md](./src/merkle_tree/README.md)

## Utils

### Hashers:

Hashing functions used for hashing inside accumulators.

- keccak: `features = ["keccak"]`

- poseidon: `features = ["poseidon"]`

- pedersen: `features = ["pedersen"]`

### Stores:

Key value stores used for storing the accumulator data.

- memory: `features = ["memory"]`

- sqlite: `features = ["sqlite"]`

## Reference

- [accumulators - CoreMMR](https://github.com/HerodotusDev/accumulators)
- [cairo_lib - MMR](https://github.com/HerodotusDev/cairo-lib/tree/main/src/data_structures)

## License

`accumulators` is licensed under the [GNU General Public License v3.0](./LICENSE).

---

Herodotus Dev Ltd - 2024
