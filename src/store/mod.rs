//! Storage layer of the crate: the [`Store`] trait, the [`InStoreTable`] and
//! [`InStoreCounter`] abstractions built on top of it, and ready-made store
//! implementations (in-memory and SQLite).

mod core;
pub use self::core::*;
mod counter;
pub use self::counter::*;
mod table;
pub use self::table::*;

mod stores;
#[allow(unused_imports)]
pub use self::stores::*;
