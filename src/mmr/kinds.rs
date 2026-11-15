//! Type-state markers for MMR variants.
//!
//! Variant-specific *methods* are gated by the kind parameter of
//! [`super::Mmr`]: a plain MMR has no commit/discard, a draft is a distinct
//! wrapper type, and a peaks-only MMR surfaces its provenance restriction in
//! the type. Value-dependent rules (e.g. "leaf 3 is below the seed point")
//! are inherently runtime checks and return typed errors — the type-state
//! covers what the compiler *can* check: which operations exist at all.

/// Marker trait for MMR kinds. Sealed: the crate defines all kinds.
pub trait Kind: sealed::Sealed {}

/// A plain MMR: built from genesis, full history, single store.
#[derive(Clone, Copy, Debug, Default)]
pub struct Plain;

/// An MMR created from peaks only: valid root, provable only above the seed
/// size.
#[derive(Clone, Copy, Debug, Default)]
pub struct WithPeaks;

/// A stacked (branched) MMR: reads route through pinned sub-MMR views.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stacked;

impl Kind for Plain {}

impl Kind for WithPeaks {}

impl Kind for Stacked {}

/// Kinds whose handle is a **single store layer**: [`Plain`] and
/// [`WithPeaks`]. [`Stacked`] handles are multi-layer, so their pins carry
/// the whole flattened chain (see [`super::stacked::SubView`]).
pub trait SingleLayerKind: Kind {}

impl SingleLayerKind for Plain {}
impl SingleLayerKind for WithPeaks {}

/// Kinds on which **deep** nullification is available.
///
/// Deep records propagate to every stack above the owning layer. A
/// [`WithPeaks`] MMR cannot deep-nullify — shallow only — and this is
/// enforced at compile time: `nullify_deep` does not exist for it.
pub trait DeepNullifiable: Kind {}

impl DeepNullifiable for Plain {}
impl DeepNullifiable for Stacked {}

/// Kinds on which the [`Editable`](crate::mmr::Editable) mode may be
/// instantiated: base-level kinds with node data for the full provable
/// range.
///
/// [`Stacked`] is excluded — in-place edits under a stack pin would
/// silently corrupt every layer above. Sealed like [`Kind`]: the
/// `update`/`delete` impl blocks are gated on this trait, so
/// `Mmr<_, _, Stacked, Editable>` is structurally unconstructible, not just
/// missing a constructor.
pub trait EditableKind: Kind {}

impl EditableKind for Plain {}
impl EditableKind for WithPeaks {}

mod sealed {
    // Sealed trait: deliberately unnameable from outside the crate.
    #[expect(
        unnameable_types,
        reason = "sealing requires the trait to be unnameable"
    )]
    pub trait Sealed {}
    impl Sealed for super::Plain {}
    impl Sealed for super::WithPeaks {}
    impl Sealed for super::Stacked {}
}
