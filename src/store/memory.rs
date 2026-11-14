//! In-memory key-value store — the reference [`Store`] backend.
//!
//! Zero-latency, infallible, and clone-cheap (`Clone` shares the backing
//! map). Two participation modes:
//!
//! - [`InMemoryStore::new`] — a standalone store; clones share its data.
//! - [`InMemoryStore::shared`] — a named store registered in a process-wide
//!   registry, so [`Retrievable::open`] can reconstruct it (the missing
//!   piece for session-local stacked MMRs). The registry holds `Weak`
//!   handles: a shared store disappears once every handle is dropped.
//!
//! The same-store hint is `Arc` pointer equality — clones of one store are
//! recognized as one storage for cross-layer batching.

use crate::store::{Batch, Op, Retrievable, Storage, Store, StoreLocator};
use alloc::sync::Arc;
use alloc::vec::Vec;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;

type SharedMap = Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>;

/// Process-wide registry for named memory stores: locator → live instance.
type Registry = RwLock<HashMap<Vec<u8>, std::sync::Weak<Mutex<HashMap<Vec<u8>, Vec<u8>>>>>>;

fn registry() -> &'static Registry {
    static REGISTRY: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// An in-memory key-value store.
#[derive(Clone)]
pub struct InMemoryStore {
    map: SharedMap,
    locator: StoreLocator,
}

impl core::fmt::Debug for InMemoryStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InMemoryStore(...)")
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    /// Creates a standalone store. Clones share the same data.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: Arc::new(Mutex::new(HashMap::new())),
            locator: StoreLocator::from_bytes(Vec::new()),
        }
    }

    /// Creates (or joins) a named store: another `shared` call with the same
    /// locator within the process lifetime yields the same data, and
    /// [`Retrievable::open`] reconstructs the store from its locator. This
    /// is what lets session-local stacks re-open their layers.
    #[must_use]
    pub fn shared(locator: impl Into<StoreLocator>) -> Self {
        let locator = locator.into();
        let key = locator.as_bytes().to_vec();
        let mut registry = registry().write();
        let map = if let Some(map) = registry.get(&key).and_then(std::sync::Weak::upgrade) {
            map
        } else {
            let map: SharedMap = Arc::new(Mutex::new(HashMap::new()));
            registry.insert(key, Arc::downgrade(&map));
            map
        };
        Self { map, locator }
    }

    /// Removes every entry (test convenience).
    pub fn clear(&self) {
        self.map.lock().clear();
    }
}

impl Storage for InMemoryStore {
    type Error = core::convert::Infallible;
}

impl Store for InMemoryStore {
    fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        let map = self.map.lock();
        Ok(keys.iter().map(|key| map.get(*key).cloned()).collect())
    }

    fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        let mut map = self.map.lock();
        for op in batch.ops {
            match op {
                Op::Put { key, value } => {
                    map.insert(key.into_owned(), value.into_owned());
                }
                Op::Delete { key } => {
                    map.remove(key.as_ref());
                }
            }
        }
        Ok(())
    }

    fn same_store(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.map, &other.map)
    }

    fn locator(&self) -> Option<StoreLocator> {
        Some(self.locator.clone())
    }
}

impl Retrievable for InMemoryStore {
    fn canonical_locator(&self) -> StoreLocator {
        self.locator.clone()
    }

    fn open(locator: &StoreLocator) -> Result<Self, Self::Error> {
        // Named stores resolve through the registry; an unknown locator
        // yields a fresh empty store under that name (session-scoped
        // semantics — there is nothing to persist to).
        Ok(Self::shared(StoreLocator::from_bytes(
            locator.as_bytes().to_vec(),
        )))
    }
}
