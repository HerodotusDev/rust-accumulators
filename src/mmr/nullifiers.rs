//! The parallel nullifier records backing [`Nullifying`](crate::mmr::Nullifying)-mode
//! MMRs.
//!
//! Deliberately **not** a cryptographic structure — no SMT, no proofs, no
//! root. Nullifiers are policy, not cryptography: on-chain they are a map
//! `(mmr id, leaf id) => mmr size at nullification`, and here they are the
//! same shape — records in the nullifying MMR's own store
//! ([`Table::Nullifiers`](crate::store::keys::Table::Nullifiers):
//! subkey = leaf index, value = size at nullification, `u64` BE). One batched
//! read resolves any number of leaves.
//!
//! # Two depths
//!
//! - `NullifierDepth::Shallow` — the record stores the size at
//!   nullification. Through stacks, a sub-MMR's shallow record is respected
//!   **only when its size ≤ the stack point**: a nullification made after
//!   the stack point is later history, invisible through the pin (exactly
//!   like appends beyond the pin size).
//! - `NullifierDepth::Deep` — the record stores `0` ("always applies").
//!   Any stacked MMR on top is influenced regardless of when the
//!   nullification happened.
//!
//! # Where records live
//!
//! - **Shallow**: in the store of the **topmost MMR operated on** (its own
//!   id), never in a deeper sub-MMR's store.
//! - **Deep**: in the store of the **layer that holds the nullified value**
//!   (the owning sub-MMR if the leaf lies below a stack point), so every
//!   stacked MMR above sees it.
//!
//! Worked example (both depths): MMR 1 grows to size 10, node 8 is nullified
//! (record `(1, 8) → 10`), grows to 12; MMR 2 stacks on MMR 1 at size 12.
//! MMR 1 grows to 20 and node 3 is nullified.
//!
//! - *Shallow* nullify of 3: record `(1, 3) → 20`. MMR 2 refuses 8 (10 ≤ 12)
//!   but still proves 3 (20 > 12); MMR 1 refuses both.
//! - *Deep* nullify of 3: record `(1, 3) → 0`. MMR 2 refuses 3 as well —
//!   deep records apply through any stack.
//!
//! # Record conflicts
//!
//! Records only ever **strengthen**: a deep record overrides an existing
//! shallow one (deep is strictly stronger); shallow over deep is a no-op;
//! among shallows the first wins (sizes only grow, so the earlier — smaller —
//! size is the more restrictive one). Sizes only ever grow, so a stored
//! shallow size can never need lowering.
//!
//! # No enumeration
//!
//! Records are keyed point lookups over the minimal
//! `Store` contract,
//! which has no prefix scan — there is deliberately no "enumerate all
//! records" here. Bulk audit use cases need a store-level scan of the
//! `Nullifiers` table (possible because the key layout is public and
//! deterministic).
//!
//! # Single-writer assumption
//!
//! Recording is a **non-atomic read-modify-write** (read the existing
//! record, put only if the candidate strengthens it) through `&self`
//! receivers. Under a single writer per `(store, id, leaf)` this is exactly
//! the strengthen-only semantics documented above; with *concurrent
//! writers*, the read and the put can interleave and a weaker record can
//! overwrite a stronger one written in between (deep → shallow regression).
//! The store contract's atomicity is per batch, not per read-modify-write
//! cycle — serialize nullification per accumulator (one handle, or one
//! writer per store) rather than relying on this type for exclusion.

use super::layout::MmrSize;
use crate::ids::TreeId;
use crate::primitives::LeafIndex;
use crate::store::{AsyncStore, Storage, Store, keys};
use alloc::vec::Vec;

/// Failures of nullifier-record operations.
///
/// Its own enum (not raw `S::Error`) because two failure modes are not
/// store failures: the wire format defines size `0` as *deep*, so a shallow
/// record with size `0` would silently upgrade itself — that is a caller
/// bug, rejected with [`NullifierError::ZeroShallowSize`]; and a stored
/// record that no longer parses as a size ([`NullifierError::MalformedRecord`])
/// must fail closed, never read as "not nullified".
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NullifierError<S: Storage> {
    /// Store I/O failed.
    #[error("store error")]
    Store(#[source] S::Error),

    /// `nullify_shallow` was called with size `0` — the wire format's deep
    /// marker. Shallow records always carry the real size at nullification
    /// (call [`NullifierSet::nullify_deep`](NullifierSet::nullify_deep) for deep semantics).
    #[error("shallow nullification cannot use size 0: 0 is the deep marker")]
    ZeroShallowSize,

    /// A nullifier record exists but cannot be parsed (not a `u64` BE
    /// size). Treated as an error, never as "not nullified" — a corrupt
    /// record that silently resolved as absent would fail open.
    #[error("nullifier record is malformed")]
    MalformedRecord,
}

/// How far a nullification reaches through stacks.
///
/// Internal encoding for buffered draft operations and record writes; the
/// public method surface is split (`nullify_shallow` / `nullify_deep`) so
/// kind restrictions (no deep nullification on `WithPeaks`) are compile-time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum NullifierDepth {
    /// Applies from the recorded size onward; through stacks, respected only
    /// when `size ≤` the stack point.
    Shallow,
    /// Applies regardless of stack points (stored as size `0`).
    Deep,
}

/// A stored nullifier record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NullifierRecord {
    /// Shallow nullification at the given MMR size.
    Shallow {
        /// MMR size at nullification; respected through a stack only when
        /// this is ≤ the stack point.
        at: MmrSize,
    },
    /// Deep nullification — applies through any stack.
    Deep,
}

impl NullifierRecord {
    /// Parses one stored record: a `u64` BE size (`0` = deep).
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        crate::store::record::parse_counter(bytes).map(Self::from_encoded)
    }

    /// The wire value: size at nullification, `0` for deep.
    pub(crate) const fn encoded(self) -> u64 {
        match self {
            Self::Shallow { at } => at.get(),
            Self::Deep => 0,
        }
    }

    /// Rebuilds from the wire value (`0` = deep).
    pub(crate) const fn from_encoded(raw: u64) -> Self {
        if raw == 0 {
            Self::Deep
        } else {
            Self::Shallow {
                at: MmrSize::new_unchecked(raw),
            }
        }
    }

    /// Whether this record resolves for a viewer pinned at `stack_point`
    /// (`usize::MAX` = own view, nothing pinned).
    pub(crate) const fn resolves_at(self, stack_point: u64) -> bool {
        match self {
            Self::Deep => true,
            Self::Shallow { at } => at.get() <= stack_point,
        }
    }
}

/// A borrowed view of the nullifier records of one MMR (its own records
/// only — stacked resolution walks sub-views itself).
///
/// # Single-writer assumption
///
/// The write path is a non-atomic read-modify-write through `&self` (see the
/// module docs): concurrent writers to the same records can regress a deep
/// record to shallow. Records only strengthen under one writer per
/// accumulator — serialize nullification, don't share this handle across
/// writing threads.
pub struct NullifierSet<'s, S, Id> {
    pub(crate) store: &'s S,
    pub(crate) id: Id,
}

// Id summary only — the borrowed store is never rendered.
impl<Id: TreeId, S> core::fmt::Debug for NullifierSet<'_, S, Id> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NullifierSet")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<S: Store, Id: TreeId> NullifierSet<'_, S, Id> {
    /// The MMR id these records belong to.
    #[must_use]
    pub const fn id(&self) -> Id {
        self.id
    }

    /// Records a **shallow** nullification of `leaf` at size `at`.
    /// Idempotent: an existing deep record is kept (`Ok(false)` returned); an
    /// existing shallow record is kept only if its size is ≤ `at` —
    /// `Ok(true)` means a record was written, `Ok(false)` means the existing
    /// record was kept.
    ///
    /// One batch write (single record put).
    ///
    /// # Errors
    ///
    /// [`NullifierError::ZeroShallowSize`] for `at == 0`,
    /// [`NullifierError::MalformedRecord`] for a corrupt existing record,
    /// store failures otherwise.
    pub fn nullify_shallow(&self, leaf: LeafIndex, at: MmrSize) -> Result<bool, NullifierError<S>> {
        if at.get() == 0 {
            return Err(NullifierError::ZeroShallowSize);
        }
        nullify_record(self.store, self.id, leaf, NullifierRecord::Shallow { at })
    }

    /// Records a **deep** nullification of `leaf` (applies through any
    /// stack). Idempotent; also **upgrades** an existing shallow record to
    /// deep, since deep is strictly stronger. `Ok(true)` = record written or
    /// upgraded, `Ok(false)` = an existing deep record was kept.
    ///
    /// # Errors
    ///
    /// [`NullifierError::MalformedRecord`] for a corrupt existing record,
    /// store failures otherwise.
    pub fn nullify_deep(&self, leaf: LeafIndex) -> Result<bool, NullifierError<S>> {
        nullify_record(self.store, self.id, leaf, NullifierRecord::Deep)
    }

    /// The nullifier record for `leaf`, if any.
    ///
    /// # Errors
    ///
    /// [`NullifierError::MalformedRecord`] for a present-but-unparsable
    /// record, store failures otherwise.
    pub fn record(&self, leaf: LeafIndex) -> Result<Option<NullifierRecord>, NullifierError<S>> {
        read_record(self.store, self.id, leaf)
    }

    /// Batch lookup: records for many leaves, positionally aligned.
    ///
    /// # Errors
    ///
    /// As [`Self::record`].
    pub fn records<I>(&self, leaves: I) -> Result<Vec<Option<NullifierRecord>>, NullifierError<S>>
    where
        I: IntoIterator<Item = LeafIndex>,
    {
        let leaves: Vec<LeafIndex> = leaves.into_iter().collect();
        read_records(self.store, self.id, &leaves)
    }
}

/// Reads records for many leaves in **one batched read**, positionally
/// aligned with `leaves`. A present-but-unparsable record is
/// [`NullifierError::MalformedRecord`] — it must never read as "not
/// nullified" (fail-open).
pub(crate) fn read_records<S: Store, Id: TreeId>(
    store: &S,
    id: Id,
    leaves: &[LeafIndex],
) -> Result<Vec<Option<NullifierRecord>>, NullifierError<S>> {
    if leaves.is_empty() {
        return Ok(Vec::new());
    }
    let keys: Vec<Vec<u8>> = leaves
        .iter()
        .map(|leaf| keys::encode(&id, keys::Table::Nullifiers, leaf.get()))
        .collect();
    let key_refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    store
        .read(&key_refs)
        .map_err(NullifierError::Store)?
        .into_iter()
        .map(|value| match value {
            None => Ok(None),
            Some(bytes) => NullifierRecord::parse(&bytes)
                .map(Some)
                .ok_or(NullifierError::MalformedRecord),
        })
        .collect()
}

/// Reads one record (shared by the sync set and the async shell). A
/// present-but-unparsable record is [`NullifierError::MalformedRecord`] —
/// it must never read as "not nullified" (fail-open).
pub(crate) fn read_record<S: Store, Id: TreeId>(
    store: &S,
    id: Id,
    leaf: LeafIndex,
) -> Result<Option<NullifierRecord>, NullifierError<S>> {
    Ok(read_records(store, id, &[leaf])?
        .into_iter()
        .next()
        .flatten())
}

/// Reads records for many leaves through an async store in one batched
/// read (positional). See [`read_records`] for the malformed-record rule.
pub(crate) async fn read_records_async<S: AsyncStore, Id: TreeId>(
    store: &S,
    id: Id,
    leaves: &[LeafIndex],
) -> Result<Vec<Option<NullifierRecord>>, NullifierError<S>> {
    if leaves.is_empty() {
        return Ok(Vec::new());
    }
    let keys: Vec<Vec<u8>> = leaves
        .iter()
        .map(|leaf| keys::encode(&id, keys::Table::Nullifiers, leaf.get()))
        .collect();
    let key_refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    store
        .read(&key_refs)
        .await
        .map_err(NullifierError::Store)?
        .into_iter()
        .map(|value| match value {
            None => Ok(None),
            Some(bytes) => NullifierRecord::parse(&bytes)
                .map(Some)
                .ok_or(NullifierError::MalformedRecord),
        })
        .collect()
}

/// Reads one record through an async store (shared by the async shell).
/// See [`read_records`] for the malformed-record rule.
pub(crate) async fn read_record_async<S: AsyncStore, Id: TreeId>(
    store: &S,
    id: Id,
    leaf: LeafIndex,
) -> Result<Option<NullifierRecord>, NullifierError<S>> {
    Ok(read_records_async(store, id, &[leaf])
        .await?
        .into_iter()
        .next()
        .flatten())
}

/// Writes one record with strengthen-only conflict resolution (shared by the
/// sync set and the async shell). Returns whether a record was written.
pub(crate) fn nullify_record<S: Store, Id: TreeId>(
    store: &S,
    id: Id,
    leaf: LeafIndex,
    record: NullifierRecord,
) -> Result<bool, NullifierError<S>> {
    match read_record(store, id, leaf)? {
        Some(existing) if existing.strength_over(record) => Ok(false),
        _ => {
            let key = keys::encode(&id, keys::Table::Nullifiers, leaf.get());
            let mut batch = crate::store::Batch::new();
            batch.put_owned(key, crate::store::record::counter(record.encoded()));
            store.write(batch).map_err(NullifierError::Store)?;
            Ok(true)
        }
    }
}

/// Writes many records in **one batched write** with strengthen-only
/// conflict resolution: duplicate requests merge first (strongest wins —
/// identical to sequential [`nullify_record`] calls, whose merge is a max
/// over the records' total order), existing records are read in one
/// batched call, and only records that strengthen what is stored are put.
///
/// `keys` must align positionally with `records` (pre-encoded by the
/// caller, which owns the id/store routing).
///
/// # Errors
///
/// [`NullifierError::MalformedRecord`] for a corrupt existing record, store
/// failures otherwise.
#[cfg(feature = "draft_mmr")]
pub(crate) fn write_records<S: Store>(
    store: &S,
    keys: Vec<Vec<u8>>,
    records: Vec<NullifierRecord>,
) -> Result<(), NullifierError<S>> {
    // Merge duplicate-key requests: the strongest candidate wins, matching
    // sequential writes where each later op must strengthen the earlier
    // one's record.
    let mut deduped_keys: Vec<Vec<u8>> = Vec::with_capacity(keys.len());
    let mut candidates: Vec<NullifierRecord> = Vec::with_capacity(keys.len());
    let mut slot_of: alloc::collections::BTreeMap<alloc::vec::Vec<u8>, usize> =
        alloc::collections::BTreeMap::new();
    for (key, record) in keys.into_iter().zip(records) {
        if let Some(&slot) = slot_of.get(&key) {
            candidates[slot] = candidates[slot].stronger(record);
        } else {
            slot_of.insert(key.clone(), candidates.len());
            deduped_keys.push(key);
            candidates.push(record);
        }
    }

    // One batched read of what is stored; a put is emitted only when the
    // candidate strengthens it.
    let key_refs: Vec<&[u8]> = deduped_keys.iter().map(Vec::as_slice).collect();
    let existing = store.read(&key_refs).map_err(NullifierError::Store)?;
    let mut batch = crate::store::Batch::new();
    for (key, (candidate, stored)) in deduped_keys
        .into_iter()
        .zip(candidates.into_iter().zip(existing))
    {
        if stored
            .as_deref()
            .and_then(NullifierRecord::parse)
            .is_some_and(|stored| stored.strength_over(candidate))
        {
            continue;
        }
        batch.put_owned(key, crate::store::record::counter(candidate.encoded()));
    }
    if batch.is_empty() {
        return Ok(());
    }
    store.write(batch).map_err(NullifierError::Store)
}

/// Async counterpart of [`nullify_record`].
pub(crate) async fn nullify_record_async<S: AsyncStore, Id: TreeId>(
    store: &S,
    id: Id,
    leaf: LeafIndex,
    record: NullifierRecord,
) -> Result<bool, NullifierError<S>> {
    match read_record_async(store, id, leaf).await? {
        Some(existing) if existing.strength_over(record) => Ok(false),
        _ => {
            let key = keys::encode(&id, keys::Table::Nullifiers, leaf.get());
            let mut batch = crate::store::Batch::new();
            batch.put_owned(key, crate::store::record::counter(record.encoded()));
            store.write(batch).await.map_err(NullifierError::Store)?;
            Ok(true)
        }
    }
}

impl NullifierRecord {
    /// Whether the existing record should be kept over `candidate`
    /// (records only strengthen; see the module docs).
    pub(crate) fn strength_over(self, candidate: Self) -> bool {
        match (self, candidate) {
            (Self::Deep, _) => true,
            (Self::Shallow { .. }, Self::Deep) => false,
            (Self::Shallow { at: current }, Self::Shallow { at }) => current.get() <= at.get(),
        }
    }

    /// The stronger of two records: deep overrides shallow; among shallows
    /// the smaller — more restrictive — size wins (equal sizes keep `self`,
    /// the first-seen record).
    pub(crate) fn stronger(self, other: Self) -> Self {
        if self.strength_over(other) {
            self
        } else {
            other
        }
    }
}
