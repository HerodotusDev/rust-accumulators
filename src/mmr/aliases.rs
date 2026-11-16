//! Shorthand handle types: one alias per valid kind × mode combination.
//!
//! Spelling [`Mmr`] or [`AsyncMmr`] with both
//! type-state parameters takes four generics; each alias here pins the kind
//! and the mode, leaving hasher, store, and — optionally — the id. The set
//! mirrors what the type-states can construct: every mode for
//! [`Plain`](super::Plain) and [`WithPeaks`](super::WithPeaks),
//! [`Stackable`](super::Stackable) modes only for
//! [`Stacked`](super::Stacked) — on the sync handle and the async shell
//! alike.

use super::AsyncMmr;
use super::Mmr;
use crate::ids::AccumulatorId;

/// A [`Plain`](super::Plain) + [`AppendOnly`](super::AppendOnly) MMR — the
/// classic accumulator and the crate's default.
pub type PlainAppendMmr<H, S, Id = AccumulatorId> = Mmr<H, S, super::Plain, super::AppendOnly, Id>;

/// A [`Plain`](super::Plain) + [`Editable`](super::Editable) MMR: in-place
/// leaf rewrites over full history.
pub type PlainEditableMmr<H, S, Id = AccumulatorId> = Mmr<H, S, super::Plain, super::Editable, Id>;

/// A [`Plain`](super::Plain) + [`Nullifying`](super::Nullifying) MMR:
/// deletes recorded as nullifiers, deep records available.
pub type PlainNullifyingMmr<H, S, Id = AccumulatorId> =
    Mmr<H, S, super::Plain, super::Nullifying, Id>;

/// A [`WithPeaks`](super::WithPeaks) + [`AppendOnly`](super::AppendOnly)
/// MMR: a peaks-only seed that only grows.
pub type WithPeaksAppendMmr<H, S, Id = AccumulatorId> =
    Mmr<H, S, super::WithPeaks, super::AppendOnly, Id>;

/// A [`WithPeaks`](super::WithPeaks) + [`Editable`](super::Editable) MMR:
/// in-place leaf rewrites above the seed floor.
pub type WithPeaksEditableMmr<H, S, Id = AccumulatorId> =
    Mmr<H, S, super::WithPeaks, super::Editable, Id>;

/// A [`WithPeaks`](super::WithPeaks) + [`Nullifying`](super::Nullifying)
/// MMR: shallow nullification only (no deep records).
pub type WithPeaksNullifyingMmr<H, S, Id = AccumulatorId> =
    Mmr<H, S, super::WithPeaks, super::Nullifying, Id>;

/// A [`Stacked`](super::Stacked) + [`AppendOnly`](super::AppendOnly) MMR:
/// pinned sub-views, no mutation of history.
#[cfg(feature = "stacked_mmr")]
pub type StackedAppendMmr<H, S, Id = AccumulatorId> =
    Mmr<H, S, super::Stacked, super::AppendOnly, Id>;

/// A [`Stacked`](super::Stacked) + [`Nullifying`](super::Nullifying) MMR:
/// pinned sub-views whose top layer mutates only through nullifiers.
#[cfg(feature = "stacked_mmr")]
pub type StackedNullifyingMmr<H, S, Id = AccumulatorId> =
    Mmr<H, S, super::Stacked, super::Nullifying, Id>;

/// An async [`Plain`](super::Plain) + [`AppendOnly`](super::AppendOnly) MMR
/// — the async twin of [`PlainAppendMmr`].
pub type AsyncPlainAppendMmr<H, S, Id = AccumulatorId> =
    AsyncMmr<H, S, super::Plain, super::AppendOnly, Id>;

/// An async [`Plain`](super::Plain) + [`Editable`](super::Editable) MMR —
/// the async twin of [`PlainEditableMmr`].
pub type AsyncPlainEditableMmr<H, S, Id = AccumulatorId> =
    AsyncMmr<H, S, super::Plain, super::Editable, Id>;

/// An async [`Plain`](super::Plain) + [`Nullifying`](super::Nullifying) MMR
/// — the async twin of [`PlainNullifyingMmr`].
pub type AsyncPlainNullifyingMmr<H, S, Id = AccumulatorId> =
    AsyncMmr<H, S, super::Plain, super::Nullifying, Id>;

/// An async [`WithPeaks`](super::WithPeaks) +
/// [`AppendOnly`](super::AppendOnly) MMR — the async twin of
/// [`WithPeaksAppendMmr`].
pub type AsyncWithPeaksAppendMmr<H, S, Id = AccumulatorId> =
    AsyncMmr<H, S, super::WithPeaks, super::AppendOnly, Id>;

/// An async [`WithPeaks`](super::WithPeaks) +
/// [`Editable`](super::Editable) MMR — the async twin of
/// [`WithPeaksEditableMmr`].
pub type AsyncWithPeaksEditableMmr<H, S, Id = AccumulatorId> =
    AsyncMmr<H, S, super::WithPeaks, super::Editable, Id>;

/// An async [`WithPeaks`](super::WithPeaks) +
/// [`Nullifying`](super::Nullifying) MMR — the async twin of
/// [`WithPeaksNullifyingMmr`].
pub type AsyncWithPeaksNullifyingMmr<H, S, Id = AccumulatorId> =
    AsyncMmr<H, S, super::WithPeaks, super::Nullifying, Id>;

/// An async [`Stacked`](super::Stacked) + [`AppendOnly`](super::AppendOnly)
/// MMR — the async twin of [`StackedAppendMmr`].
#[cfg(feature = "stacked_mmr")]
pub type AsyncStackedAppendMmr<H, S, Id = AccumulatorId> =
    AsyncMmr<H, S, super::Stacked, super::AppendOnly, Id>;

/// An async [`Stacked`](super::Stacked) + [`Nullifying`](super::Nullifying)
/// MMR — the async twin of [`StackedNullifyingMmr`].
#[cfg(feature = "stacked_mmr")]
pub type AsyncStackedNullifyingMmr<H, S, Id = AccumulatorId> =
    AsyncMmr<H, S, super::Stacked, super::Nullifying, Id>;
