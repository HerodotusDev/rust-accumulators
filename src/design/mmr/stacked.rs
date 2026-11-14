//! Stacked (branched) MMRs: unlimited layering over pinned sub-MMR views.
//!
//! The owner's model: MMR 2 stacks on MMR 1 at size 11 (covers 0–10), MMR 3
//! stacks on MMR 2 at size 15 (covers 0–14), and every layer keeps growing
//! independently — the stack reads each sub-MMR *up to its pin size*, so
//! independent growth below the pin is invisible above it. One hasher across
//! all layers.
//!
//! # Stores across layers
//!
//! All layers share one store *type* `S` (different *instances* are fine).
//! Two escape hatches:
//!
//! - **Mixed store types**: wrap every layer — top included — in
//!   [`crate::design::store::ErasedStore`] and build the stack over
//!   `S = ErasedStore` (see [`SubView::erased`]). Erased stacks are
//!   session-local.
//! - **Persistence**: opening a stacked MMR reconstructs every layer's
//!   store from persisted locators, which requires the store type to
//!   implement [`Retrievable`] — see [`open_stacked`].
//!
//! # Smart batching
//!
//! Multi-store operations — stacked proofs, multiproofs, draft commits with
//! deep nullifier records — are planned **once, at construction**, never
//! per call:
//!
//! 1. A layer's store identity is its locator
//!    ([`Retrievable::locator`]). Layers resolving to the same locator join
//!    one group; identity is resolved a single time when the stack is built
//!    and never changes at runtime.
//! 2. At operation time the router issues exactly **one batched call per
//!    distinct store**: same-identity groups are merged, identical keys are
//!    deduplicated, and results are fanned back through a precomputed index
//!    map.
//! 3. Distinct stores execute in parallel — joined futures on the async
//!    shell, sequential on the sync one.
//!
//! Because grouping is precomputed, merging same-identity groups is
//! strictly no slower than issuing one call per group: fewer or equal
//! calls, and zero per-operation merge overhead. The "merge only when it is
//! faster" question is answered by construction, not by a runtime guess.
//! What remains a store-side responsibility is making one big batched call
//! efficient — chunking to backend limits (e.g. SQLite's variable cap),
//! multi-get, pipelining. The accumulator always makes exactly one logical
//! call per distinct store and must not care how the store executes it.
//!
//! The plan must still be *measured*, not assumed: stacked multi-store
//! scenarios (single shared store vs. all-distinct vs. mixed) are part of
//! the benchmark re-baseline.
//!
//!
//! v0.5 defects this design fixes:
//! - metadata was a loose `Vec<(usize, MmrMetadata)>` with only the last
//!   entry validated — unsorted or overlapping sizes silently routed reads
//!   to the wrong sub-MMR ([`SubView`] is validated at construction here),
//! - routing was mutable public fn-pointers on the table layer — here it is
//!   private, immutable state inside the [`Stacked`](crate::design::mmr::Stacked) kind,
//! - single vs multi-key routing could diverge — one routing function.

use alloc::vec::Vec;

use super::mode::Stackable;
use crate::design::hashers::Hasher;
use crate::design::ids::TreeId;
use crate::design::primitives::{HashValue, MmrSize, NodeIndex};
use crate::design::store::{ErasedStore, Retrievable, Storage, Store, StoreLocator};

/// A frozen, read-only view of a sub-MMR at a pinned size.
///
/// Produced by [`super::Mmr::pin`]. Reads through this view only ever see
/// nodes below the pin size, regardless of the sub-MMR's later growth.
pub struct SubView<S, Id, O = crate::design::primitives::Hash> {
    /// The sub-MMR's id (its keys in its store).
    pub(crate) id: Id,
    /// The sub-MMR's store.
    pub(crate) store: S,
    /// Node count at pin time: the exclusive read ceiling routed here.
    pub(crate) pinned_size: MmrSize,
    pub(crate) _output: core::marker::PhantomData<fn() -> O>,
}

impl<S, Id: Copy, O: HashValue> SubView<S, Id, O> {
    /// The pinned node count.
    #[must_use]
    pub const fn pinned_size(&self) -> MmrSize {
        self.pinned_size
    }

    /// The sub-MMR's id.
    #[must_use]
    pub const fn id(&self) -> Id {
        self.id
    }
}

impl<S: Store, Id: TreeId, O: HashValue> SubView<S, Id, O> {
    /// Reads node hashes, clipping to the pin size: indexes at or above
    /// [`Self::pinned_size`] return `None` even if the sub-MMR has grown
    /// past it since the pin.
    ///
    /// Crate-internal: the stacked router is the only reader; the public
    /// proof APIs speak [`LeafIndex`](crate::design::primitives::LeafIndex).
    ///
    /// # Errors
    ///
    /// Store failures.
    pub(crate) fn load_nodes(&self, nodes: &[NodeIndex]) -> Result<Vec<Option<O>>, S::Error> {
        let _ = nodes;
        todo!()
    }

    /// Erases the view's store, for building mixed-type stacks (every layer
    /// wrapped; see the module docs). Session-local by nature.
    #[must_use]
    pub fn erased(self) -> SubView<ErasedStore, Id, O>
    where
        S: Send + Sync + 'static,
    {
        todo!()
    }
}

impl<S: Retrievable, Id, O> SubView<S, Id, O> {
    /// The sub-store's locator — persisted in the stacked metadata, used by
    /// [`open_stacked`] to reconstruct the layer, and by routing to identify
    /// shared stores for batch coalescing.
    #[must_use]
    pub fn locator(&self) -> StoreLocator {
        todo!()
    }
}

/// Re-opens a stacked MMR from its persisted sub-view metadata
/// ([`keys::Table::Subviews`](crate::design::store::keys::Table::Subviews)):
/// each layer's id, pin size, and store locator.
///
/// `store` is the **top layer's store** — the one holding the `Subviews`
/// record under the stacked MMR's own id. Every sub-layer is re-opened via
/// [`Retrievable::open`] with the same `S` — persistent stacks therefore
/// require a concrete retrievable store type (erased stacks are
/// session-local). The declared mode `M` and the hasher identity/config are
/// validated against the persisted metadata, and pin sizes are
/// cross-checked against each layer's own counters.
///
/// # Errors
///
/// Store re-open failures or missing/corrupt metadata
/// ([`MmrError::Corrupted`](super::MmrError::Corrupted)).
pub fn open_stacked<H: Hasher, S: Retrievable, M: Stackable, Id: TreeId>(
    hasher: H,
    store: S,
    id: Id,
) -> Result<super::Mmr<H, S, super::Stacked, M, Id>, super::MmrError<S>> {
    let _ = (&hasher, &store, id);
    todo!()
}

/// Validates and orders sub-views for stacking.
///
/// Requirements enforced here (all were silently violated in v0.5):
/// - pin sizes strictly increasing, no duplicates,
/// - the top MMR's own range starts at the largest pin size,
/// - every view's range is well-formed for an MMR (valid node count).
///
/// Called by [`Mmr::stack`](super::Mmr::stack); public so callers can
/// pre-validate a view set before committing to construction.
///
/// # Errors
///
/// See above; the error names the offending pair of pin sizes.
pub fn validate_sub_views<S: Store, Id: TreeId, O: HashValue>(
    views: &[SubView<S, Id, O>],
) -> Result<(), SubViewsError> {
    let _ = views;
    todo!()
}

/// Sub-view list rejected by [`validate_sub_views`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SubViewsError {
    /// Two views share a pin size.
    #[error("duplicate pin size {size}")]
    DuplicateSize {
        /// The duplicated pin size.
        size: MmrSize,
    },
    /// Pin sizes are not strictly increasing.
    #[error("pin sizes must strictly increase: {prev} then {next}")]
    Unsorted {
        /// The earlier pin size.
        prev: MmrSize,
        /// The following, smaller pin size.
        next: MmrSize,
    },
    /// A pin size is not a valid MMR node count.
    #[error("pin size {size} is not a valid MMR size")]
    InvalidSize {
        /// The rejected raw size.
        size: u64,
    },
    /// No views supplied.
    #[error("at least one sub-view is required")]
    Empty,
}

/// Stacking construction failures. Generic over [`Storage`] — shares the
/// sync/async error-unification model of
/// [`MmrError`](super::MmrError).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StackingError<S: Storage> {
    /// Sub-view list invalid.
    #[error(transparent)]
    SubViews(#[from] SubViewsError),
    /// Store I/O failed.
    #[error("store error")]
    Store(#[source] S::Error),
}
