//! Concurrent fan-out for stacked-layer reads across distinct stores.
//!
//! The stacked routers plan every read as one batched call per distinct
//! store ([`same_store`](crate::store::Store::same_store) grouping). These
//! helpers drive those per-store batches concurrently on the polling task
//! and assemble the results in input order, so output and error identity
//! match the sequential walk exactly: every future is driven to completion
//! (nothing is cancelled mid-read) and the first error in input order wins —
//! the same error the sequential path would surface first.
//!
//! The sync shell keeps sequential execution: [`Store`](crate::store::Store)
//! carries no thread-safety bound, so sharing `&S` across
//! `std::thread::scope` threads is not expressible without new public
//! bounds. Write paths stay sequential in both shells: nullifier commits are
//! read-modify-write per store, and `same_store` is a performance hint —
//! concurrency there would trade the documented sequential-commit semantics
//! on a lying backend.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::Poll;

/// One boxed per-store batch future, as every fan-out site hands it over.
/// `Send` comes from the store traits' own future contracts — no `Sync`
/// bound on the store is required.
pub(crate) type BatchFuture<'f, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'f>>;

/// Drives every future to completion on the polling task and returns the
/// results in input order.
///
/// The first error in input order wins — the same error a sequential walk
/// would surface first. Futures are never cancelled: every batch runs to
/// completion even when an earlier one already failed. Concurrency is
/// bounded by the caller's batch count (one future per distinct store).
pub(crate) async fn join_ordered<T, E>(
    mut futures: Vec<BatchFuture<'_, T, E>>,
) -> Result<Vec<T>, E> {
    let mut slots: Vec<Option<Result<T, E>>> = (0..futures.len()).map(|_| None).collect();

    core::future::poll_fn(|cx| {
        let mut pending = false;
        for (index, future) in futures.iter_mut().enumerate() {
            if slots[index].is_some() {
                continue;
            }
            match future.as_mut().poll(cx) {
                Poll::Ready(result) => slots[index] = Some(result),
                Poll::Pending => pending = true,
            }
        }
        if pending {
            return Poll::Pending;
        }
        // All batches finished: the first error in input order wins.
        let mut values = Vec::with_capacity(slots.len());
        let mut error = None;
        for slot in &mut slots {
            match slot.take() {
                Some(Ok(value)) if error.is_none() => values.push(value),
                Some(Err(err)) if error.is_none() => error = Some(err),
                // Later results are dropped once an error won; the arm also
                // covers the unreachable empty slot (`pending == false`
                // implies every slot resolved).
                _ => {}
            }
        }
        match error {
            Some(error) => Poll::Ready(Err(error)),
            None => Poll::Ready(Ok(values)),
        }
    })
    .await
}
