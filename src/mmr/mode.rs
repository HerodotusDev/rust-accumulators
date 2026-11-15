//! Mutability modes — the second type-state axis of the MMR.
//!
//! Kind ([`Plain`](crate::mmr::Plain) / [`WithPeaks`](crate::mmr::WithPeaks) /
//! [`Stacked`](crate::mmr::Stacked)) says *where an MMR's history comes from*.
//! Mode says *what may happen to its leaves after they exist*. The two are
//! orthogonal: `Mmr<H, S, K, M>`, with `M = AppendOnly` by default so the
//! common case stays `Mmr<PoseidonStarkHasher, MyStore>`.
//!
//! # The three modes
//!
//! - [`AppendOnly`] — the classic MMR. `update` / `delete` do not exist on
//!   the type; a call that would mutate history is a **compile error**.
//! - [`Editable`] — leaves can be rewritten in place (`update`) or cleared
//!   (`delete`). Each edit recomputes the leaf's path to the root and
//!   persists in one batch write. Scope restrictions (enforced at runtime,
//!   since they are value-dependent):
//!
//!   - `Plain`: every leaf editable.
//!   - `WithPeaks`: only leaves above the seed size — below it there is no
//!     node data to recompute from (mirrors the proof restriction).
//!
//!   Editable MMRs are **base-use only**: they cannot be stacked upon, and
//!   the `Stacked` kind cannot be editable — both are compile-time
//!   impossibilities (see [`Stackable`]). In-place edits under a stack pin
//!   would silently corrupt every layer above; stacked accumulators mutate
//!   only through [`Nullifying`].
//! - [`Nullifying`] — the data stays append-only forever; "deletes" and
//!   "overwrites" are recorded as nullifier records in a parallel table
//!   ([`super::nullifiers::NullifierSet`]):
//!   - `nullify_shallow(leaf)` writes `(mmr id, leaf) → size at
//!     nullification` into the operated-on (topmost) MMR's store; works for
//!     every kind, for any index below the leaf count (including below a
//!     `WithPeaks` floor — records are index-keyed, no content needed).
//!   - `nullify_deep(leaf)` writes `(owner id, leaf) → 0` into the store of
//!     the layer that **holds the value**, so every stack above is
//!     influenced regardless of when the nullification happened. Available
//!     for Plain and Stacked only — a `WithPeaks` MMR cannot deep-nullify
//!     ([`super::DeepNullifiable`], compile-time).
//!   - `replace_shallow` / `replace_deep` = the matching nullify + append.
//!   - Proofs for nullified leaves are refused
//!     ([`super::MmrError::LeafNullified`]). Through stacks, sub-MMR records
//!     resolve only when their size ≤ the stack point: a nullification made
//!     after the stack point is later history, invisible through the pin.
//!
//! # Mode is explicit and persisted
//!
//! The mode is chosen at construction, written into metadata, and validated
//! against the caller's declared mode on `open` — an `AppendOnly` open of an
//! `Editable` MMR is a hard [`Corrupted::ModeMismatch`](super::Corrupted)
//! error, not a silent capability downgrade.

/// Marker trait for mutability modes. Sealed: the crate defines all modes.
pub trait Mode: sealed::Sealed {
    /// Whether deletion is recorded as a nullifier write instead of a data
    /// change.
    const NULLIFYING: bool;
    /// Canonical name, persisted in metadata and validated on open.
    const NAME: &'static str;
}

/// Modes that may participate in **stacking** — as a pinned base (via
/// `pin`) or as the stacked layer's own mode.
///
/// [`Editable`] is excluded by design: an in-place edit under a stack pin
/// silently corrupts every layer stacked above (a pin freezes size, not
/// content), and nobody can know what was stacked on an edited MMR. Stacking
/// on an editable MMR is therefore unconstructible, and stacked accumulators
/// mutate only through [`Nullifying`].
pub trait Stackable: Mode {}

impl Stackable for AppendOnly {}
impl Stackable for Nullifying {}

/// Leaves are written once and never change. The default mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct AppendOnly;

/// Leaves can be rewritten in place or cleared.
#[derive(Clone, Copy, Debug, Default)]
pub struct Editable;

/// Data is append-only; deletes and overwrites are recorded as nullifiers in
/// a parallel set.
#[derive(Clone, Copy, Debug, Default)]
pub struct Nullifying;

impl Mode for AppendOnly {
    const NULLIFYING: bool = false;
    const NAME: &'static str = "append_only";
}

impl Mode for Editable {
    const NULLIFYING: bool = false;
    const NAME: &'static str = "editable";
}

impl Mode for Nullifying {
    const NULLIFYING: bool = true;
    const NAME: &'static str = "nullifying";
}

mod sealed {
    // Sealed trait: deliberately unnameable from outside the crate.
    #[expect(
        unnameable_types,
        reason = "sealing requires the trait to be unnameable"
    )]
    pub trait Sealed {}
    impl Sealed for super::AppendOnly {}
    impl Sealed for super::Editable {}
    impl Sealed for super::Nullifying {}
}
