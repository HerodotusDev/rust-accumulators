//! The parallel nullifier records backing [`Nullifying`](crate::design::mmr::Nullifying)-mode
//! MMRs.
//!
//! Deliberately **not** a cryptographic structure — no SMT, no proofs, no
//! root. Nullifiers are policy, not cryptography: on-chain they are a map
//! `(mmr id, leaf id) => mmr size at nullification`, and here they are the
//! same shape — records in the nullifying MMR's own store
//! ([`keys::Table::Nullifiers`](crate::design::store::keys::Table::Nullifiers):
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

use crate::design::ids::TreeId;
use crate::design::primitives::{LeafIndex, MmrSize};
use crate::design::store::Storage;
use alloc::vec::Vec;

/// Failures of nullifier-record operations.
///
/// Its own enum (not raw `S::Error`) because one failure mode is not a
/// store failure at all: the wire format defines size `0` as *deep*, so a
/// shallow record with size `0` would silently upgrade itself — that is a
/// caller bug, rejected with [`NullifierError::ZeroShallowSize`].
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

/// A borrowed view of the nullifier records of one MMR (its own records
/// only — stacked resolution walks sub-views itself).
///
/// Note: records are keyed point lookups over the minimal
/// [`Store`](crate::design::store::Store) contract,
/// which has no prefix scan — there is deliberately no "enumerate all
/// records" here. Bulk audit use cases need a store-level scan of the
/// `Nullifiers` table (possible because the key layout is public and
/// deterministic).
pub struct NullifierSet<'s, S, Id> {
    pub(crate) store: &'s S,
    pub(crate) id: Id,
}

impl<'s, S: crate::design::store::Store, Id: TreeId> NullifierSet<'s, S, Id> {
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
    /// [`NullifierError::ZeroShallowSize`] for `at == 0`, store failures
    /// otherwise.
    pub fn nullify_shallow(&self, leaf: LeafIndex, at: MmrSize) -> Result<bool, NullifierError<S>> {
        let _ = (leaf, at);
        todo!()
    }

    /// Records a **deep** nullification of `leaf` (applies through any
    /// stack). Idempotent; also **upgrades** an existing shallow record to
    /// deep, since deep is strictly stronger. `Ok(true)` = record written or
    /// upgraded, `Ok(false)` = an existing deep record was kept.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub fn nullify_deep(&self, leaf: LeafIndex) -> Result<bool, NullifierError<S>> {
        let _ = leaf;
        todo!()
    }

    /// The nullifier record for `leaf`, if any.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub fn record(&self, leaf: LeafIndex) -> Result<Option<NullifierRecord>, NullifierError<S>> {
        let _ = leaf;
        todo!()
    }

    /// Batch lookup: records for many leaves, positionally aligned.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub fn records<I>(&self, leaves: I) -> Result<Vec<Option<NullifierRecord>>, NullifierError<S>>
    where
        I: IntoIterator<Item = LeafIndex>,
    {
        let _ = leaves;
        todo!()
    }
}
