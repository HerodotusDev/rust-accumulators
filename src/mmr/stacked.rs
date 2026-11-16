//! Stacked (branched) MMRs: unlimited layering over pinned sub-MMR views.
//!
//! MMR 2 stacks on MMR 1 at size 11 (covers 0–10), MMR 3 stacks on MMR 2 at
//! size 15 (covers 0–14), and every layer keeps growing independently — the
//! stack reads each sub-MMR *up to its pin size*, so independent growth
//! below the pin is invisible above it. One hasher across all layers.
//!
//! # Layer routing
//!
//! Every node index belongs to exactly one layer: the first pinned view whose
//! pin size covers it, or the stacked MMR's own layer above the largest pin.
//! Reads and writes are grouped **by store** — layers whose stores are
//! [`same_store`](crate::store::Store::same_store) join one batched call —
//! so a whole stack on one shared store costs exactly one I/O call per
//! operation, and distinct stores cost one call each: concurrently in the
//! async shells (a shared fan-out helper joins the per-store batches, with
//! the sequential error identity), sequentially in the sync shell, whose
//! store contract carries no cross-thread guarantee. The grouping runs per
//! operation over a layer list that never changes after construction.
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

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::layout::{MmrSize, NodeIndex};
#[cfg(feature = "stacked_mmr")]
use super::mode::{AppendOnly, Nullifying, Stackable};
#[cfg(feature = "stacked_mmr")]
use crate::hashers::Hasher;
use crate::ids::TreeId;
use crate::primitives::HashValue;
#[cfg(feature = "stacked_mmr")]
use crate::store::Retrievable;
use crate::store::{
    AsyncStore, ErasedAsyncStore, ErasedStore, Storage, Store, StoreLocator, keys, keys::Table,
};
#[cfg(feature = "stacked_mmr")]
use alloc::boxed::Box;

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
#[expect(
    missing_debug_implementations,
    reason = "generic over non-Debug stores; a manual Debug would have to render or hide the store"
)]
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
    #[expect(
        clippy::expect_used,
        reason = "every view is constructed with at least one layer (see # Panics)"
    )]
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
    ///
    /// The layer's locator is derived exactly as `Mmr::pin` derives it: from
    /// [`Store::locator`] of the given store — `None` for session-local
    /// backends, the re-openable canonical locator for persisted ones. To
    /// hand-pin a locator instead (rare; proxying cases), chain
    /// [`SubView::with_locator`].
    ///
    /// # Trust model
    ///
    /// Unlike `Mmr::pin`, this constructor is forgeable: the id, store, and
    /// pinned size are taken on trust, and the content is checked only when
    /// the view is read or stacked (missing nodes surface as
    /// `Corrupted::MissingRecord` / `StackingError` at stacking time, never
    /// as silently-wrong routing — routing is derived from `pinned_size`
    /// alone, which the caller owns).
    #[must_use]
    pub fn single(id: Id, store: S, pinned_size: MmrSize) -> Self
    where
        S: Store,
    {
        let locator = Store::locator(&store);
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

    /// Async-shell twin of [`SubView::single`]: a single-layer view over an
    /// [`AsyncStore`], with the layer's locator derived exactly as the async
    /// `AsyncMmr::pin` derives it (from [`AsyncStore::locator`] — `None`
    /// for session-local backends). Same trust model: forgeable shape, the
    /// content is checked at read/stack time.
    #[must_use]
    pub fn single_async(id: Id, store: S, pinned_size: MmrSize) -> Self
    where
        S: AsyncStore,
    {
        let locator = AsyncStore::locator(&store);
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

    /// Replaces the top layer's locator with a hand-pinned one — the escape
    /// hatch for proxying cases where the store's own locator does not name
    /// the re-openable storage (`None` marks the layer session-local).
    #[must_use]
    pub fn with_locator(mut self, locator: Option<StoreLocator>) -> Self {
        if let Some(layer) = self.layers.last_mut() {
            layer.locator = locator;
        }
        self
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

/// One routed read group: a store, the **deduplicated** node keys to read
/// there, and the result positions each key fills.
pub(crate) struct RouteGroup<'a, S> {
    /// The store to read from.
    pub(crate) store: &'a S,
    /// Encoded node keys (per layer id), deduplicated in request order.
    pub(crate) keys: Vec<Vec<u8>>,
    /// `slots[i]` holds every result position filled by `keys[i]` — one key
    /// can serve several requests (overlapping proof paths).
    pub(crate) slots: Vec<Vec<usize>>,
}

/// Pure layer routing + store grouping for a batch of node reads: nodes at
/// or below a sub-view's pin route through its chain (innermost covering
/// layer), everything else to the own layer; same-store layers merge into
/// one group with keys deduplicated. Execution — the actual read and the
/// fan-back — stays with the sync and async shells.
/// `same_store` is the caller's [`Store::same_store`](crate::store::Store::same_store)
/// / [`AsyncStore::same_store`](crate::store::AsyncStore::same_store) —
/// the two traits define it separately, so the planner takes it as a hook.
pub(crate) fn plan_node_reads<'a, S, Id: TreeId, O: HashValue>(
    subs: &'a [SubView<S, Id, O>],
    own_store: &'a S,
    own_id: Id,
    nodes: &[NodeIndex],
    same_store: impl Fn(&S, &S) -> bool,
) -> Vec<RouteGroup<'a, S>> {
    let mut groups: Vec<RouteGroup<'a, S>> = Vec::new();
    // Per-group dedup index: (layer id, node) → slot in the group's keys.
    let mut seen: Vec<BTreeMap<(Id, u64), usize>> = Vec::new();

    for (position, node) in nodes.iter().enumerate() {
        // Each sub-view routes internally through its own (possibly
        // multi-layer) chain; the own layer handles everything above the
        // pins. A sub covering the node without a covering layer leaves the
        // request unrouted (result stays `None`).
        let mut routed = None;
        let mut covered = false;
        for sub in subs {
            if node.get() <= sub.pinned_size.get() {
                if let Some(layer) = sub.route(node.get()) {
                    routed = Some((layer.store_ref(), layer.id_ref()));
                }
                covered = true;
                break;
            }
        }
        let (store, id) = match (routed, covered) {
            (Some(target), _) => target,
            (None, false) => (own_store, own_id),
            (None, true) => continue,
        };

        let key = keys::encode(&id, Table::Nodes, node.get());
        let existing = groups
            .iter_mut()
            .zip(&mut seen)
            .find(|(group, _)| same_store(group.store, store));
        if let Some((group, seen)) = existing {
            if let Some(&slot) = seen.get(&(id, node.get())) {
                group.slots[slot].push(position);
            } else {
                seen.insert((id, node.get()), group.keys.len());
                group.keys.push(key);
                group.slots.push(vec![position]);
            }
        } else {
            groups.push(RouteGroup {
                store,
                keys: vec![key],
                slots: vec![vec![position]],
            });
            seen.push(BTreeMap::from([((id, node.get()), 0_usize)]));
        }
    }
    groups
}

/// Parses one stored node value: `None` = absent; a present value must
/// parse as a hash. Present-but-unparsable is corruption, never an absent
/// key — the shared read helper for the sync shell, the async shell, and
/// the router.
pub(crate) fn parse_node_value<S: Storage, O: HashValue>(
    value: Option<Vec<u8>>,
) -> Result<Option<O>, super::MmrError<S>> {
    match value {
        None => Ok(None),
        Some(bytes) => O::from_bytes(&bytes)
            .map(Some)
            .ok_or(super::MmrError::Corrupted(
                super::Corrupted::MalformedRecord {
                    table: Table::Nodes,
                },
            )),
    }
}

impl<S: Store, Id: TreeId, O: HashValue> SubView<S, Id, O> {
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

impl<S: AsyncStore, Id: TreeId, O: HashValue> SubView<S, Id, O> {
    /// Async-shell twin of [`SubView::erased`]: erases the view's store
    /// into [`ErasedAsyncStore`] for building mixed-type async stacks
    /// (every layer wrapped). Session-local by nature.
    #[must_use]
    pub fn erased_async(self) -> SubView<ErasedAsyncStore, Id, O>
    where
        S: AsyncStore + Send + Sync + 'static,
    {
        SubView {
            layers: self
                .layers
                .into_iter()
                .map(|layer| LayerView {
                    id: layer.id,
                    store: ErasedAsyncStore::new(layer.store),
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

/// Validates that every layer of every sub-view persists a hasher identity +
/// config matching the stack's hasher. A stack whose layers hash with a
/// different identity or configuration does not reproduce the reference root
/// of the same elements, so this runs at stack construction *and* at every
/// stacked re-open. Cold path: one single-key read per layer.
///
/// Returns the first mismatching layer's recorded identity
/// (`"name (config)"`), or `None` when all layers match.
#[cfg(feature = "stacked_mmr")]
pub(crate) fn first_layer_hasher_mismatch<H: Hasher, S: Store, Id: TreeId, O: HashValue>(
    subs: &[SubView<S, Id, O>],
    hasher: &H,
) -> Option<alloc::string::String> {
    for sub in subs {
        for layer in &sub.layers {
            let key = keys::encode(&layer.id_ref(), Table::HasherInfo, 0);
            let values = layer.store_ref().read(&[&key]);
            let stored = match values {
                // Unreadable store: the identity cannot be confirmed —
                // report a mismatch rather than swallowing the finding.
                Ok(values) => match values.into_iter().next().flatten() {
                    Some(stored) => stored,
                    None => {
                        return Some(alloc::string::ToString::to_string("missing hasher record"));
                    }
                },
                Err(_) => return Some(alloc::format!("{} ({})", hasher.id(), hasher.config())),
            };
            let Some((stored_id, stored_config)) = crate::store::record::parse_hasher_info(&stored)
            else {
                return Some(alloc::string::ToString::to_string(
                    "unreadable hasher record",
                ));
            };
            if stored_id != hasher.id() || stored_config != hasher.config() {
                return Some(alloc::format!("{stored_id} ({stored_config})"));
            }
        }
    }
    None
}

/// Async-shell twin of [`first_layer_hasher_mismatch`] over
/// [`AsyncStore`] layers; same contract, awaited reads. The per-layer
/// reads run concurrently and the findings are evaluated in layer order,
/// so the reported mismatch is exactly the sequential walk's first one.
#[cfg(feature = "stacked_mmr")]
pub(crate) async fn first_layer_hasher_mismatch_async<
    H: Hasher,
    S: AsyncStore,
    Id: TreeId,
    O: HashValue,
>(
    subs: &[SubView<S, Id, O>],
    hasher: &H,
) -> Option<alloc::string::String> {
    let record_keys: Vec<Vec<u8>> = subs
        .iter()
        .flat_map(|sub| sub.layers.iter())
        .map(|layer| keys::encode(&layer.id_ref(), Table::HasherInfo, 0))
        .collect();
    let key_refs: Vec<[&[u8]; 1]> = record_keys.iter().map(|key| [key.as_slice()]).collect();

    #[expect(
        clippy::type_complexity,
        reason = "the boxed per-store batch type is named once at use"
    )]
    let mut futures: Vec<super::fanout::BatchFuture<'_, Vec<Option<Vec<u8>>>, S::Error>> =
        Vec::with_capacity(key_refs.len());
    for (layer, refs) in subs.iter().flat_map(|sub| sub.layers.iter()).zip(&key_refs) {
        futures.push(Box::pin(layer.store_ref().read(refs)));
    }
    let Ok(loaded) = super::fanout::join_ordered(futures).await else {
        // Unreadable store: the identity cannot be confirmed — report a
        // mismatch rather than swallowing the finding (the first error in
        // layer order wins, as in the sequential walk).
        return Some(alloc::format!("{} ({})", hasher.id(), hasher.config()));
    };

    for values in loaded {
        let Some(stored) = values.into_iter().next().flatten() else {
            return Some(alloc::string::ToString::to_string("missing hasher record"));
        };
        let Some((stored_id, stored_config)) = crate::store::record::parse_hasher_info(&stored)
        else {
            return Some(alloc::string::ToString::to_string(
                "unreadable hasher record",
            ));
        };
        if stored_id != hasher.id() || stored_config != hasher.config() {
            return Some(alloc::format!("{stored_id} ({stored_config})"));
        }
    }
    None
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

    // Reconstruct the sub-views exactly as `pin()` had them: distinct pin
    // sizes (ascending) are the view boundaries, and a view with pin P
    // carries every flattened layer whose pin is ≤ P, in bottom → top order
    // (a view's pin is always its top layer's pinned size). Rebuilding one
    // single-layer view per record instead would produce duplicate pins —
    // which `validate_sub_views` (run by `open_stack`) rightly rejects.
    let mut pins: Vec<u64> = layers.iter().map(|layer| layer.pinned_size).collect();
    pins.sort_unstable();
    pins.dedup();

    let mut subs = Vec::with_capacity(pins.len());
    for &pin in &pins {
        let mut chain: Vec<LayerView<S, Id, H::Output>> = Vec::new();
        for layer in &layers {
            if layer.pinned_size > pin {
                continue;
            }
            let layer_store = S::open(&layer.locator).map_err(super::MmrError::Store)?;
            // Cross-check: the layer must actually hold at least the pinned
            // size.
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
            if node_count < layer.pinned_size {
                return Err(super::MmrError::Corrupted(
                    super::Corrupted::PinSizeMismatch {
                        pinned: MmrSize::new_unchecked(layer.pinned_size),
                        layer_size: MmrSize::new_unchecked(node_count),
                    },
                ));
            }
            chain.push(LayerView {
                id: layer.id,
                store: layer_store,
                pinned_size: MmrSize::new_unchecked(layer.pinned_size),
                locator: Some(layer.locator.clone()),
                _output: core::marker::PhantomData,
            });
        }
        subs.push(SubView {
            layers: chain,
            pinned_size: MmrSize::new_unchecked(pin),
            _output: core::marker::PhantomData,
        });
    }

    super::Mmr::open_stack(hasher, store, id, subs)
}

/// Re-opens a stacked MMR whose top layer is [`AppendOnly`] — the named
/// alternative to the four-parameter [`open_stacked`] turbofish.
///
/// # Errors
///
/// As [`open_stacked`].
#[cfg(feature = "stacked_mmr")]
pub fn open_stacked_append_only<H: Hasher, S: Retrievable, Id: TreeId>(
    hasher: H,
    store: S,
    id: Id,
) -> Result<super::Mmr<H, S, super::Stacked, AppendOnly, Id>, super::MmrError<S>> {
    open_stacked::<H, S, AppendOnly, Id>(hasher, store, id)
}

/// Re-opens a stacked MMR whose top layer is [`Nullifying`] — the named
/// alternative to the four-parameter [`open_stacked`] turbofish.
///
/// # Errors
///
/// As [`open_stacked`].
#[cfg(feature = "stacked_mmr")]
pub fn open_stacked_nullifying<H: Hasher, S: Retrievable, Id: TreeId>(
    hasher: H,
    store: S,
    id: Id,
) -> Result<super::Mmr<H, S, super::Stacked, Nullifying, Id>, super::MmrError<S>> {
    open_stacked::<H, S, Nullifying, Id>(hasher, store, id)
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
/// Requirements enforced here:
/// - pin sizes strictly increasing, no duplicates,
/// - the top MMR's own range starts at the largest pin size,
/// - every view's range is well-formed for an MMR (valid node count).
///
/// Called by [`super::Mmr::stack`]; public so callers can
/// pre-validate a view set before committing to construction. Store-trait
/// agnostic: it reads only the views' pin sizes, so it serves the sync and
/// async shells alike.
///
/// # Errors
///
/// See above; the error names the offending pair of pin sizes.
#[cfg(feature = "stacked_mmr")]
pub fn validate_sub_views<S, Id: TreeId, O: HashValue>(
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
    /// A sub-view's pinned peak nodes are absent or unparsable in its
    /// store: the view's shape is valid but its content does not back the
    /// pin ([`SubView::single`] is a forgeable constructor).
    #[error("a pinned peak node is missing from its layer's store")]
    MissingPeakNodes,
    /// No views supplied.
    #[error("at least one sub-view is required")]
    Empty,
}

/// Stacking construction failures, generic over [`Storage`] like
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
    /// The hasher's identity/config cannot be represented in the persisted
    /// `HasherInfo` record (custom name over 255 bytes or config over
    /// 65535 bytes) — rejected at creation instead of persisting a record
    /// that would brick every later open.
    #[error("hasher identity cannot be represented in the persisted record")]
    UnrepresentableHasher,
    /// A pinned layer's persisted hasher identity/config differs from the
    /// stack's hasher — the stack root would not equal the reference root of
    /// the same elements, so the stack is refused at construction (and at
    /// re-open, as a [`Corrupted::HasherMismatch`](super::Corrupted)).
    #[error("stacked layer hasher mismatch: store has {stored}")]
    LayerHasherMismatch {
        /// The layer's recorded hasher identity/config.
        stored: alloc::string::String,
    },
}
