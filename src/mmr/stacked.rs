//! Stacked (branched) MMRs: unlimited layering over pinned sub-MMR views.
//!
//! The owner's model: MMR 2 stacks on MMR 1 at size 11 (covers 0–10), MMR 3
//! stacks on MMR 2 at size 15 (covers 0–14), and every layer keeps growing
//! independently — the stack reads each sub-MMR *up to its pin size*, so
//! independent growth below the pin is invisible above it. One hasher across
//! all layers.
//!
//! # Layer routing
//!
//! Every node index belongs to exactly one layer: the first pinned view whose
//! pin size covers it, or the stacked MMR's own layer above the largest pin.
//! Reads and writes are grouped **by store** — layers whose stores are
//! [`same_store`](crate::store::Store::same_store) join one batched call —
//! so a whole stack on one shared store costs exactly one I/O call per
//! operation, and distinct stores cost one call each (sequential for now; a
//! parallel fan-out is future work). The grouping runs per operation over a
//! layer list that never changes after construction.
//!
//! # Stores across layers
//!
//! All layers share one store *type* `S` (different *instances* are fine).
//! Two escape hatches:
//!
//! - **Mixed store types**: wrap every layer — top included — in
//!   [`crate::store::ErasedStore`] and build the stack over
//!   `S = ErasedStore` (see [`SubView::erased`]). Erased stacks are
//!   session-local.
#![cfg_attr(
    feature = "stacked_mmr",
    doc = "- **Persistence**: opening a stacked MMR reconstructs every layer's\n  store from persisted locators, which requires the store type to\n  implement [`Retrievable`] — see [`open_stacked`].\n"
)]
//!
//! v0.5 defects this design fixes:
//! - metadata was a loose `Vec<(usize, MmrMetadata)>` with only the last
//!   entry validated — unsorted or overlapping sizes silently routed reads
//!   to the wrong sub-MMR ([`SubView`] is validated at construction here),
//! - routing was mutable public fn-pointers on the table layer — here it is
//!   private, immutable state inside the [`Stacked`](crate::mmr::Stacked) kind,
//! - single vs multi-key routing could diverge — one routing function.

use alloc::vec;
use alloc::vec::Vec;

use super::layout::{MmrSize, NodeIndex};
#[cfg(feature = "stacked_mmr")]
use super::mode::Stackable;
use super::nullifiers::{NullifierRecord, read_record};
#[cfg(feature = "stacked_mmr")]
use crate::hashers::Hasher;
use crate::ids::TreeId;
use crate::primitives::{HashValue, LeafIndex};
use crate::store::{ErasedStore, Store, StoreLocator, keys, keys::Table};
#[cfg(feature = "stacked_mmr")]
use crate::store::{Retrievable, Storage};

/// A frozen, read-only view of a sub-MMR at a pinned size.
///
/// Produced by `Mmr::pin`. Reads through this view only ever see
/// nodes below the pin size, regardless of the sub-MMR's later growth.
///
/// A view of a **stacked** MMR carries the whole flattened layer chain (each
/// inner layer with its own pin), so pinning a stack and stacking it further
/// preserves the routing — one [`SubView`] is always a complete, self-
/// contained read path for everything below its pin.
#[derive(Clone)]
pub struct SubView<S, Id, O = crate::primitives::Hash> {
    /// The layer chain, innermost (deepest) first; the last entry is the
    /// pinned sub-MMR's own top layer.
    pub(crate) layers: Vec<LayerView<S, Id, O>>,
    /// Node count at pin time: the exclusive read ceiling routed here.
    pub(crate) pinned_size: MmrSize,
    pub(crate) _output: core::marker::PhantomData<fn() -> O>,
}

/// One routed layer of a [`SubView`]: an accumulator id, its store, and the
/// node-count ceiling that routes reads to it.
#[derive(Clone)]
pub(crate) struct LayerView<S, Id, O> {
    /// The layer's id (its keys in its store).
    pub(crate) id: Id,
    /// The layer's store.
    pub(crate) store: S,
    /// Node count at pin time: nodes ≤ this ceiling route here.
    pub(crate) pinned_size: MmrSize,
    /// Canonical locator captured at pin time (`None` for session-local
    /// backends) — persisted in the stacked metadata.
    pub(crate) locator: Option<StoreLocator>,
    pub(crate) _output: core::marker::PhantomData<fn() -> O>,
}

impl<S, Id: Copy, O> LayerView<S, Id, O> {
    /// The layer's store.
    pub(crate) const fn store_ref(&self) -> &S {
        &self.store
    }

    /// The layer's id.
    pub(crate) const fn id_ref(&self) -> Id {
        self.id
    }
}

impl<S, Id: Copy, O: HashValue> SubView<S, Id, O> {
    /// The pinned node count.
    #[must_use]
    pub const fn pinned_size(&self) -> MmrSize {
        self.pinned_size
    }

    /// The pinned sub-MMR's own id (its top layer's keys in its store).
    ///
    /// # Panics
    ///
    /// Never in practice: every view is constructed with at least one layer.
    #[must_use]
    pub fn id(&self) -> Id {
        self.layers.last().expect("a view always has layers").id
    }

    /// The layer covering `node`, innermost first — `None` beyond the pin
    /// (growth past the pin stays invisible).
    pub(crate) fn route(&self, node: u64) -> Option<&LayerView<S, Id, O>> {
        self.layers
            .iter()
            .find(|layer| node <= layer.pinned_size.get())
    }

    /// A single-layer view (pin of a `Plain`/`WithPeaks` MMR).
    #[must_use]
    pub fn single(id: Id, store: S, pinned_size: MmrSize, locator: Option<StoreLocator>) -> Self
    where
        S: Store,
    {
        Self {
            layers: vec![LayerView {
                id,
                store,
                pinned_size,
                locator,
                _output: core::marker::PhantomData,
            }],
            pinned_size,
            _output: core::marker::PhantomData,
        }
    }

    /// A store-type-changing copy of this view (used by draft
    /// `commit_as_stacked` to re-clone layer stores).
    #[cfg(feature = "draft_mmr")]
    pub(crate) fn relayered_clone(&self) -> Self
    where
        S: Clone,
    {
        Self {
            layers: self
                .layers
                .iter()
                .map(|layer| LayerView {
                    id: layer.id,
                    store: S::clone(layer.store_ref()),
                    pinned_size: layer.pinned_size,
                    locator: layer.locator.clone(),
                    _output: core::marker::PhantomData,
                })
                .collect(),
            pinned_size: self.pinned_size,
            _output: core::marker::PhantomData,
        }
    }

    /// The covering layer for a node at or below the pin — the owner of any
    /// value stored there.
    pub(crate) fn owner_of(&self, node: u64) -> Option<&LayerView<S, Id, O>> {
        self.route(node)
    }

    /// The persisted layer records of this view, innermost first.
    #[cfg(feature = "stacked_mmr")]
    pub(crate) fn persisted_layers(&self) -> impl Iterator<Item = PersistedLayer<Id>> + '_ {
        self.layers.iter().map(|layer| PersistedLayer {
            id: layer.id,
            pinned_size: layer.pinned_size.get(),
            locator: layer
                .locator
                .clone()
                .unwrap_or_else(|| StoreLocator::from_bytes(Vec::new())),
        })
    }
}

/// One routed request group: a store, the keys to read there, and the result
/// positions they fill.
struct RouterGroup<'a, S> {
    store: &'a S,
    keys: Vec<Vec<u8>>,
    positions: Vec<usize>,
}

/// The node router shared by the stacked MMR and its sub-views, so single-
/// and multi-key reads can never diverge: requests are grouped **per store**
/// (same-store layers join one batched call, keys deduplicated), and results
/// fan back positionally.
pub(crate) struct NodeRouter<'a, S> {
    groups: Vec<RouterGroup<'a, S>>,
}

impl<'a, S: Store> NodeRouter<'a, S> {
    /// An empty router.
    pub(crate) fn new() -> Self {
        Self { groups: Vec::new() }
    }

    /// Routes one node to a layer's `(store, id)`.
    pub(crate) fn route<Id: TreeId>(
        &mut self,
        store: &'a S,
        id: Id,
        node: NodeIndex,
        position: usize,
    ) {
        let key = keys::encode(&id, Table::Nodes, node.get());
        match self
            .groups
            .iter_mut()
            .find(|group| Store::same_store(group.store, store))
        {
            Some(group) => {
                group.keys.push(key);
                group.positions.push(position);
            }
            None => self.groups.push(RouterGroup {
                store,
                keys: vec![key],
                positions: vec![position],
            }),
        }
    }

    /// Executes one batched read per distinct store and fans the decoded
    /// values back into a positionally aligned result.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub(crate) fn read<O: HashValue>(self, nodes: usize) -> Result<Vec<Option<O>>, S::Error> {
        let mut results: Vec<Option<O>> = vec![None; nodes];
        for group in self.groups {
            let refs: Vec<&[u8]> = group.keys.iter().map(Vec::as_slice).collect();
            let values = group.store.read(&refs)?;
            for (value, position) in values.into_iter().zip(&group.positions) {
                results[*position] = value.and_then(|bytes| O::from_bytes(&bytes));
            }
        }
        Ok(results)
    }
}

impl<S: Store, Id: TreeId, O: HashValue> SubView<S, Id, O> {
    /// Resolves the nullifier record for `leaf` through the layer chain.
    /// Every layer's records — the pinned sub's own included — are gated by
    /// that layer's pin size: a record written after the pin carries a later
    /// size and is invisible through the view, exactly like appends past the
    /// pin.
    pub(crate) fn resolve_nullifier(
        &self,
        leaf: LeafIndex,
    ) -> Result<Option<NullifierRecord>, S::Error> {
        let node = leaf.node().get();
        for layer in &self.layers {
            if node <= layer.pinned_size.get() {
                if let Some(record) = read_record(layer.store_ref(), layer.id_ref(), leaf)?
                    && record.resolves_at(layer.pinned_size.get())
                {
                    return Ok(Some(record));
                }
                // The leaf's layer is this one; deeper layers cannot hold it.
                break;
            }
        }
        Ok(None)
    }

    /// Erases the view's store, for building mixed-type stacks (every layer
    /// wrapped; see the module docs). Session-local by nature.
    #[must_use]
    pub fn erased(self) -> SubView<ErasedStore, Id, O>
    where
        S: Store + Send + Sync + 'static,
    {
        SubView {
            layers: self
                .layers
                .into_iter()
                .map(|layer| LayerView {
                    id: layer.id,
                    store: ErasedStore::new(layer.store),
                    pinned_size: layer.pinned_size,
                    locator: layer.locator,
                    _output: core::marker::PhantomData,
                })
                .collect(),
            pinned_size: self.pinned_size,
            _output: core::marker::PhantomData,
        }
    }
}

/// Re-opens a stacked MMR from its persisted sub-view metadata
/// ([`Table::Subviews`]):
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
#[cfg(feature = "stacked_mmr")]
pub fn open_stacked<H: Hasher, S: Retrievable, M: Stackable, Id: TreeId>(
    hasher: H,
    store: S,
    id: Id,
) -> Result<super::Mmr<H, S, super::Stacked, M, Id>, super::MmrError<S>> {
    use crate::store::record::parse_counter;

    // Layer list first: it tells us where every counter lives.
    let subviews_key = keys::encode(&id, Table::Subviews, 0);
    let mut values = store
        .read(&[&subviews_key])
        .map_err(super::MmrError::Store)?;
    let Some(raw) = values.pop().flatten() else {
        return Err(super::MmrError::Corrupted(
            super::Corrupted::MissingRecord {
                table: Table::Subviews,
            },
        ));
    };
    let layers = parse_subviews(&raw).ok_or(super::MmrError::Corrupted(
        super::Corrupted::MalformedRecord {
            table: Table::Subviews,
        },
    ))?;

    let mut subs = Vec::with_capacity(layers.len());
    for layer in &layers {
        let layer_store = S::open(&layer.locator).map_err(super::MmrError::Store)?;
        // Cross-check: the layer must actually hold at least the pinned size.
        let count_key = keys::encode(&layer.id, Table::NodeCount, 0);
        let mut stored = layer_store
            .read(&[&count_key])
            .map_err(super::MmrError::Store)?;
        let node_count = stored
            .pop()
            .flatten()
            .as_deref()
            .and_then(parse_counter)
            .ok_or(super::MmrError::Corrupted(
                super::Corrupted::MissingRecord {
                    table: Table::NodeCount,
                },
            ))?;
        // Node counts are bounded by MAX_LEAF_COUNT (< 2^63); on 32-bit
        // targets an MMR wider than `usize` cannot be materialized, so the
        // narrowing into the error's `usize` fields never loses information
        // in practice.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "node counts are bounded by MAX_LEAF_COUNT (< 2^63); on 32-bit targets a larger MMR cannot be materialized"
        )]
        if node_count < layer.pinned_size {
            return Err(super::MmrError::Corrupted(
                super::Corrupted::PeaksMismatch {
                    expected: layer.pinned_size as usize,
                    found: node_count as usize,
                },
            ));
        }
        subs.push(SubView {
            layers: vec![LayerView {
                id: layer.id,
                store: layer_store,
                pinned_size: MmrSize::new_unchecked(layer.pinned_size),
                locator: Some(layer.locator.clone()),
                _output: core::marker::PhantomData,
            }],
            pinned_size: MmrSize::new_unchecked(layer.pinned_size),
            _output: core::marker::PhantomData,
        });
    }

    super::Mmr::open_stack(hasher, store, id, subs)
}

/// One persisted layer of a stacked MMR.
#[cfg(feature = "stacked_mmr")]
pub(crate) struct PersistedLayer<Id> {
    /// The layer's id.
    pub id: Id,
    /// Node count at pin time.
    pub pinned_size: u64,
    /// Canonical locator of the layer's store.
    pub locator: StoreLocator,
}

/// Encodes the `Subviews` record: bottom → top layer order.
///
/// Returns `None` when the layer set cannot be represented in the record's
/// wire format — more than [`u16::MAX`] layers, an id encoding longer than
/// [`u8::MAX`] bytes, or a locator longer than [`u16::MAX`] bytes. The caller
/// must fail rather than persist a record that cannot be parsed back.
#[cfg(feature = "stacked_mmr")]
pub(crate) fn encode_subviews<Id: TreeId>(layers: &[PersistedLayer<Id>]) -> Option<Vec<u8>> {
    let count = u16::try_from(layers.len()).ok()?;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_be_bytes());
    for layer in layers {
        let mut id_bytes = Vec::new();
        layer.id.encode_into(&mut id_bytes);
        let id_len = u8::try_from(id_bytes.len()).ok()?;
        out.push(id_len);
        out.extend_from_slice(&id_bytes);
        out.extend_from_slice(&layer.pinned_size.to_be_bytes());
        let locator = layer.locator.as_bytes();
        let locator_len = u16::try_from(locator.len()).ok()?;
        out.extend_from_slice(&locator_len.to_be_bytes());
        out.extend_from_slice(locator);
    }
    Some(out)
}

/// Decodes the `Subviews` record.
#[cfg(feature = "stacked_mmr")]
pub(crate) fn parse_subviews<Id: TreeId>(raw: &[u8]) -> Option<Vec<PersistedLayer<Id>>> {
    let count = u16::from_be_bytes(*raw.first_chunk::<2>()?) as usize;
    let mut rest = raw.get(2..)?;
    let mut layers = Vec::with_capacity(count);
    for _ in 0..count {
        let id_len = *rest.first()? as usize;
        let id_bytes = rest.get(1..1 + id_len)?;
        rest = &rest[1 + id_len..];
        let pinned_bytes: [u8; 8] = *rest.first_chunk::<8>()?;
        rest = &rest[8..];
        let locator_len_bytes: [u8; 2] = *rest.first_chunk::<2>()?;
        let locator_len = u16::from_be_bytes(locator_len_bytes) as usize;
        let locator = rest.get(2..2 + locator_len)?;
        rest = &rest[2 + locator_len..];
        layers.push(PersistedLayer {
            id: Id::from_bytes(id_bytes)?,
            pinned_size: u64::from_be_bytes(pinned_bytes),
            locator: StoreLocator::from_bytes(locator.to_vec()),
        });
    }
    Some(layers)
}

/// Validates and orders sub-views for stacking.
///
/// Requirements enforced here (all were silently violated in v0.5):
/// - pin sizes strictly increasing, no duplicates,
/// - the top MMR's own range starts at the largest pin size,
/// - every view's range is well-formed for an MMR (valid node count).
///
/// Called by [`super::Mmr::stack`]; public so callers can
/// pre-validate a view set before committing to construction.
///
/// # Errors
///
/// See above; the error names the offending pair of pin sizes.
#[cfg(feature = "stacked_mmr")]
pub fn validate_sub_views<S: Store, Id: TreeId, O: HashValue>(
    views: &[SubView<S, Id, O>],
) -> Result<(), InvalidSubViews> {
    let Some(first) = views.first() else {
        return Err(InvalidSubViews::Empty);
    };
    let mut previous = first.pinned_size.get();
    if first.pinned_size.leaf_count().is_none() {
        return Err(InvalidSubViews::InvalidSize {
            size: MmrSize::new_unchecked(previous),
        });
    }
    for view in &views[1..] {
        let size = view.pinned_size.get();
        if view.pinned_size.leaf_count().is_none() {
            return Err(InvalidSubViews::InvalidSize {
                size: MmrSize::new_unchecked(size),
            });
        }
        if size == previous {
            return Err(InvalidSubViews::DuplicateSize {
                size: MmrSize::new_unchecked(size),
            });
        }
        if size < previous {
            return Err(InvalidSubViews::Unsorted {
                prev: MmrSize::new_unchecked(previous),
                next: MmrSize::new_unchecked(size),
            });
        }
        previous = size;
    }
    Ok(())
}

/// Sub-view list rejected by [`validate_sub_views`].
#[cfg(feature = "stacked_mmr")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidSubViews {
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
        /// The rejected size.
        size: MmrSize,
    },
    /// A sub-view record exceeds the wire format's length prefixes (over
    /// 65535 layers, an id over 255 bytes, or an over-65535-byte locator).
    #[error("sub-view record exceeds the wire format's length prefixes")]
    Unrepresentable,
    /// No views supplied.
    #[error("at least one sub-view is required")]
    Empty,
}

/// Stacking construction failures. Generic over [`Storage`] — shares the
/// sync/async error-unification model of
/// [`MmrError`](super::MmrError).
#[cfg(feature = "stacked_mmr")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StackingError<S: Storage> {
    /// Sub-view list invalid.
    #[error(transparent)]
    SubViews(#[from] InvalidSubViews),
    /// Store I/O failed.
    #[error("store error")]
    Store(#[source] S::Error),
}
