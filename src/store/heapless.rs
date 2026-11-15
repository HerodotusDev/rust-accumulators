//! A fixed-capacity, allocation-free key-value store for `no_std` targets.
//!
//! [`HeaplessStore`] keeps its whole map inline — a sorted array of
//! fixed-capacity key/value buffers, sized by the const generics `N`,
//! `KEY_CAP` and `VAL_CAP` — so holding data never touches an allocator.
//! It is the storage backend for MCU-class targets (the crate's
//! `thumbv7em` story): capacity is chosen per instance in the type,
//! exhaustion is a typed error, never a panic and never a reallocation.
//!
//! # Map structure
//!
//! Entries live in one sorted [`heapless::Vec`]; lookups binary-search in
//! O(log n), inserts and deletes shift entries in O(n). At the capacities
//! this store is for (tens to a few thousand entries) a contiguous inline
//! array beats a hashed structure on every axis that matters here: no
//! hashing, no probing, no allocation, one flat memory region, ordered
//! iteration, and a fully deterministic per-operation cost.
//!
//! # Caps
//!
//! `KEY_CAP` defaults to the crate's binary key wire bound (265 bytes:
//! a `u8` length prefix + a 255-byte id + the table tag + the `u64`
//! subkey) and `VAL_CAP` to 64 bytes (32-byte hash values, `u64`
//! counters, small records). Both are const generics: shrink them for
//! compact ids (the default `AccumulatorId` needs 26-byte keys), grow
//! them for large custom records. Oversized input is a typed
//! [`HeaplessError::KeyTooLong`] / [`HeaplessError::ValueTooLong`].
//!
//! # Concurrency
//!
//! The map sits behind [`critical_section::Mutex`], the embedded-standard
//! global lock, so `&self` reads and writes are safe from any thread. Every
//! operation runs in a single critical section: on `std` hosts that is a
//! global mutex (tests and benches get the `std` implementation from a
//! dev-dependency), on bare metal it disables interrupts or takes the
//! RTOS/kernel lock — whichever implementation the target's support crate
//! provides. Writes hold the section for the whole batch, which is what
//! makes each write all-or-nothing; keep `N` and batch sizes modest on
//! MCUs to bound worst-case interrupt latency. Like every
//! `critical-section` consumer, the crate ships no implementation:
//! bare-metal binaries select one via their platform crate (e.g.
//! `cortex-m` with `critical-section-single-core`), and `std` binaries
//! that use this store enable one too — the `std` feature of
//! `critical-section` (a global mutex) or any other provider.
//!
//! # Allocation honesty
//!
//! The store's map never allocates. Two things still allocate, by
//! contract, on targets that have an allocator: the [`Store`] I/O types
//! (batches and read results are `alloc::vec::Vec`-based) and the write
//! path's scratch undo journal (freed after each batch). The accumulator
//! cores themselves build proofs on the heap, so an embedded user still
//! provides a global allocator (e.g. `embedded-alloc`) around this
//! allocation-free store — what the store removes is the *unbounded*
//! memory risk at the storage layer.
//!
//! # Semantics
//!
//! - Capacity: an insert past `N` is [`HeaplessError::Full`]. A batch that
//!   overflows is rolled back entirely — observers see the old map or the
//!   new one, never a partial application (the same all-or-nothing
//!   contract every backend must honor).
//! - [`Clone`] deep-copies the map: clones are fully independent stores
//!   (distinct identities, no shared state) — unlike the `Arc`-backed
//!   backends, where clones are handles onto one storage.
//! - Session-local like every in-RAM backend: no locator, no re-opening,
//!   nothing persisted; identity is the instance's address.

use crate::store::{Batch, Op, Storage, Store};
use alloc::vec::Vec;
use core::cell::RefCell;
use critical_section::Mutex;
use heapless::Vec as FixedVec;

/// Default per-key byte capacity: the crate's binary key wire bound
/// (`[id_len: u8][id: ≤ 255][table: u8][subkey: u64 BE]` = 265 bytes).
pub const DEFAULT_KEY_CAP: usize = 265;

/// Default per-value byte capacity: covers 32-byte hash values, `u64`
/// counters and the crate's small text/counter records with headroom.
pub const DEFAULT_VAL_CAP: usize = 64;

type Key<const KEY_CAP: usize> = FixedVec<u8, KEY_CAP>;
type Value<const VAL_CAP: usize> = FixedVec<u8, VAL_CAP>;

/// The error axis of the heapless store: capacity is the only way this
/// backend can refuse a write, and every variant is recoverable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HeaplessError {
    /// The batch would insert more new keys than the store has free
    /// entry slots (`N`); it was rolled back and nothing was written.
    #[error(
        "store is at its entry capacity of {0}; the batch was rolled back and nothing was written"
    )]
    Full(usize),
    /// A key exceeded the store's `KEY_CAP`.
    #[error("key of {len} bytes exceeds the store's key capacity of {cap} bytes")]
    KeyTooLong {
        /// The rejected key's length in bytes.
        len: usize,
        /// The store's key capacity in bytes.
        cap: usize,
    },
    /// A value exceeded the store's `VAL_CAP`.
    #[error("value of {len} bytes exceeds the store's value capacity of {cap} bytes")]
    ValueTooLong {
        /// The rejected value's length in bytes.
        len: usize,
        /// The store's value capacity in bytes.
        cap: usize,
    },
}

/// One key-value pair in fixed-capacity inline storage.
#[derive(Clone)]
struct Entry<const KEY_CAP: usize, const VAL_CAP: usize> {
    key: Key<KEY_CAP>,
    value: Value<VAL_CAP>,
}

/// The inline map: entries kept sorted by key bytes, so lookups
/// binary-search and inserts shift at most one tail.
#[derive(Clone)]
struct Entries<const N: usize, const KEY_CAP: usize, const VAL_CAP: usize> {
    items: FixedVec<Entry<KEY_CAP, VAL_CAP>, N>,
}

impl<const N: usize, const KEY_CAP: usize, const VAL_CAP: usize> Entries<N, KEY_CAP, VAL_CAP> {
    const fn new() -> Self {
        Self {
            items: FixedVec::new(),
        }
    }

    /// Position of `key` in the sorted items — `Ok` at its index when
    /// present, `Err` at the insertion point when absent.
    fn position(&self, key: &[u8]) -> Result<usize, usize> {
        self.items
            .as_slice()
            .binary_search_by(|entry| entry.key.as_slice().cmp(key))
    }

    fn get(&self, key: &[u8]) -> Option<&Value<VAL_CAP>> {
        let index = self.position(key).ok()?;
        Some(&self.items[index].value)
    }
}

/// One applied, reversible mutation — the write path's undo journal.
///
/// Keys reference the batch (no copies); values are copied out only when
/// an op overwrites or removes them (≤ `VAL_CAP` bytes, inline).
enum Undo<'a, const KEY_CAP: usize, const VAL_CAP: usize> {
    /// A brand-new key was inserted; undo by removing it.
    Inserted(&'a [u8]),
    /// An existing value was replaced; undo by restoring the old one.
    Replaced(&'a [u8], Value<VAL_CAP>),
    /// An existing entry was removed; undo by re-inserting it whole.
    Removed(Entry<KEY_CAP, VAL_CAP>),
}

impl<const KEY_CAP: usize, const VAL_CAP: usize> Undo<'_, KEY_CAP, VAL_CAP> {
    /// Reverts one applied op. Every action only reclaims capacity or
    /// re-uses a slot the mirrored op freed, so reversal cannot fail.
    fn revert<const N: usize>(self, entries: &mut Entries<N, KEY_CAP, VAL_CAP>) {
        match self {
            Undo::Inserted(key) => {
                if let Ok(index) = entries.position(key) {
                    entries.items.remove(index);
                }
            }
            Undo::Replaced(key, previous) => {
                if let Ok(index) = entries.position(key) {
                    entries.items[index].value = previous;
                }
            }
            Undo::Removed(entry) => {
                if let Err(index) = entries.position(&entry.key) {
                    debug_assert!(
                        entries.items.len() < entries.items.capacity(),
                        "undo of a delete must find the slot its op freed"
                    );
                    let _ = entries.items.insert(index, entry);
                }
            }
        }
    }
}

/// A fixed-capacity, allocation-free key-value store.
///
/// Generic over three const parameters:
///
/// - `N` — entry capacity; an insert past it fails with
///   [`HeaplessError::Full`],
/// - `KEY_CAP` — per-key byte capacity (default [`DEFAULT_KEY_CAP`]),
/// - `VAL_CAP` — per-value byte capacity (default [`DEFAULT_VAL_CAP`]).
///
/// ```
/// use accumulators::store::heapless::HeaplessStore;
/// use accumulators::store::{Batch, Store};
///
/// let store = HeaplessStore::<8>::new();
/// let mut batch = Batch::new();
/// batch.put(b"key", b"value");
/// store.write(batch).unwrap();
/// assert_eq!(store.read(&[b"key"]).unwrap(), vec![Some(b"value".to_vec())]);
/// ```
pub struct HeaplessStore<
    const N: usize,
    const KEY_CAP: usize = DEFAULT_KEY_CAP,
    const VAL_CAP: usize = DEFAULT_VAL_CAP,
> {
    entries: Mutex<RefCell<Entries<N, KEY_CAP, VAL_CAP>>>,
}

impl<const N: usize, const KEY_CAP: usize, const VAL_CAP: usize>
    HeaplessStore<N, KEY_CAP, VAL_CAP>
{
    /// Creates an empty store. `const`, so instances can live in
    /// `static`s; every instance starts with all `N` slots free.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Mutex::new(RefCell::new(Entries::new())),
        }
    }

    /// The store's entry capacity (`N`).
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// The number of live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        critical_section::with(|cs| self.entries.borrow(cs).borrow().items.len())
    }

    /// Whether the store holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes every entry, freeing all `N` slots.
    pub fn clear(&self) {
        critical_section::with(|cs| self.entries.borrow(cs).borrow_mut().items.clear());
    }

    /// Applies the batch's ops in order under one critical section. Any
    /// refusal (full map, oversized key/value) rolls back every op applied
    /// so far via the undo journal, leaving the map untouched.
    fn apply<'a>(
        entries: &mut Entries<N, KEY_CAP, VAL_CAP>,
        ops: &'a [Op<'a>],
        undo: &mut Vec<Undo<'a, KEY_CAP, VAL_CAP>>,
    ) -> Result<(), HeaplessError> {
        for op in ops {
            match op {
                Op::Put { key, value } => {
                    let (raw_key, raw_value) = (key.as_ref(), value.as_ref());
                    // The conversion from the batch bytes IS the caps check:
                    // an oversized key/value maps to its typed error.
                    let key = Key::<KEY_CAP>::from_slice(raw_key).map_err(|_| {
                        HeaplessError::KeyTooLong {
                            len: raw_key.len(),
                            cap: KEY_CAP,
                        }
                    })?;
                    let value = Value::<VAL_CAP>::from_slice(raw_value).map_err(|_| {
                        HeaplessError::ValueTooLong {
                            len: raw_value.len(),
                            cap: VAL_CAP,
                        }
                    })?;
                    match entries.position(&key) {
                        Ok(index) => {
                            let previous =
                                core::mem::replace(&mut entries.items[index].value, value);
                            undo.push(Undo::Replaced(raw_key, previous));
                        }
                        Err(index) => {
                            entries
                                .items
                                .insert(index, Entry { key, value })
                                .map_err(|_| HeaplessError::Full(N))?;
                            undo.push(Undo::Inserted(raw_key));
                        }
                    }
                }
                Op::Delete { key } => {
                    let raw_key = key.as_ref();
                    if let Ok(index) = entries.position(raw_key) {
                        undo.push(Undo::Removed(entries.items.remove(index)));
                    }
                }
            }
        }
        Ok(())
    }
}

impl<const N: usize, const KEY_CAP: usize, const VAL_CAP: usize> Default
    for HeaplessStore<N, KEY_CAP, VAL_CAP>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const KEY_CAP: usize, const VAL_CAP: usize> Clone
    for HeaplessStore<N, KEY_CAP, VAL_CAP>
{
    /// Deep-copies the map: the clone is an independent store with its own
    /// identity, not a handle onto the same data.
    fn clone(&self) -> Self {
        let entries = critical_section::with(|cs| self.entries.borrow(cs).borrow().clone());
        Self {
            entries: Mutex::new(RefCell::new(entries)),
        }
    }
}

impl<const N: usize, const KEY_CAP: usize, const VAL_CAP: usize> core::fmt::Debug
    for HeaplessStore<N, KEY_CAP, VAL_CAP>
{
    /// Bounded output: entry counts only — never the map's contents.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HeaplessStore")
            .field("entries", &self.len())
            .field("capacity", &N)
            .finish()
    }
}

impl<const N: usize, const KEY_CAP: usize, const VAL_CAP: usize> Storage
    for HeaplessStore<N, KEY_CAP, VAL_CAP>
{
    type Error = HeaplessError;
}

impl<const N: usize, const KEY_CAP: usize, const VAL_CAP: usize> Store
    for HeaplessStore<N, KEY_CAP, VAL_CAP>
{
    fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        critical_section::with(|cs| {
            let entries = self.entries.borrow(cs).borrow();
            Ok(keys
                .iter()
                .map(|&key| entries.get(key).map(|value| value.as_slice().to_vec()))
                .collect())
        })
    }

    fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        critical_section::with(|cs| {
            let entries = &mut *self.entries.borrow(cs).borrow_mut();
            let mut undo: Vec<Undo<'_, KEY_CAP, VAL_CAP>> = Vec::with_capacity(batch.ops.len());
            match Self::apply(entries, &batch.ops, &mut undo) {
                Ok(()) => Ok(()),
                // Roll back in reverse op order — each undo restores the
                // exact pre-op state, so the batch is all-or-nothing.
                Err(error) => {
                    for action in undo.into_iter().rev() {
                        action.revert(entries);
                    }
                    Err(error)
                }
            }
        })
    }
}
