//! Opt-in observation of selected outer actor polls and wake requests.
//!
//! The default build returns the original future unchanged. The optional
//! `lifecycle-task-capture` feature additionally requires the runtime setting
//! `TEMPO_LIFECYCLE_ASYNC_TASKS=selected_v1`. Only anonymous ordinals and fixed
//! role/outcome codes are emitted; a matching collector is required.
//!
//! The collector must explicitly admit `async_task_register`, `async_task_wake`,
//! `async_task_poll_begin`, `async_task_poll_end`, `async_task_terminal`, and
//! `async_task_coverage`. Their only fields are `task_id`, `task_role`, `task_poll`,
//! `task_wakes`, and `task_outcome`; timestamps and thread ordinals come from the
//! collector. Coverage failures invalidate the diagnostic, never application work.
//!
//! Wake emission occurs outside the observer lock and may race past its target
//! poll's begin or terminal event. Its generation remains identifiable, but a
//! consumer must leave such delays unavailable and never reopen a completed task.
//! Wake requests during an active poll also overlap service rather than measuring
//! pure executor waiting. Keep source cutoff, open-poll censoring and missing-record
//! checks in the collector/report path; this helper cannot establish those alone.
use commonware_macros::stability;
use std::future::Future;

#[cfg(feature = "lifecycle-task-capture")]
#[path = "lifecycle_task_enabled.rs"]
mod enabled;

/// Closed actor categories; no context labels or peer identities are recorded.
#[stability(BETA)]
#[derive(Clone, Copy, Debug)]
#[repr(u64)]
pub enum Role {
    /// Marshal actor.
    Marshal = 1,
    /// Simplex voter actor.
    Voter = 2,
    /// Simplex resolver actor.
    Resolver = 3,
    /// Simplex batch verifier actor.
    Batcher = 4,
    /// Authenticated peer sender loop.
    PeerSend = 5,
    /// Authenticated peer receiver loop.
    PeerReceive = 6,
}

/// Observe a selected outer actor future when the diagnostic is enabled.
///
/// Feature-off builds return the original future. Feature-compiled, runtime-off
/// builds forward the original Context without observer allocation but retain
/// a small enum branch per poll. Capture is bounded to 256 retained states,
/// including stale wakers; exceeding the cap invalidates observation coverage.
///
/// Wake requests are not executor enqueue events. Concurrent event publication
/// can be unordered, so the collector must retain ambiguous delays as unavailable.
/// Matching collector/header admission and strict source cutoff are required.
#[stability(BETA)]
#[inline]
pub fn observe<F: Future>(role: Role, future: F) -> impl Future<Output = F::Output> {
    #[cfg(feature = "lifecycle-task-capture")]
    {
        enabled::observe(role, future)
    }
    #[cfg(not(feature = "lifecycle-task-capture"))]
    {
        let _ = role;
        future
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::Mutex;
    use std::{
        cell::Cell,
        marker::PhantomPinned,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll, Waker},
    };

    struct PinnedActor {
        address: Cell<Option<usize>>,
        wake: Arc<Mutex<Option<Waker>>>,
        ready: Arc<AtomicBool>,
        _pin: PhantomPinned,
    }
    impl Future for PinnedActor {
        type Output = u64;
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u64> {
            let current = self.as_ref().get_ref() as *const Self as usize;
            if let Some(previous) = self.address.replace(Some(current)) {
                assert!(previous == current, "pinned future moved");
            }
            *self.wake.lock() = Some(cx.waker().clone());
            if self.ready.load(Ordering::Acquire) {
                Poll::Ready(23)
            } else {
                Poll::Pending
            }
        }
    }

    #[test]
    fn lifecycle_task_public_actor_future_preserves_send_and_pin() {
        fn require_send<T: Send>(_: &T) {}
        let wake = Arc::new(Mutex::new(None));
        let ready = Arc::new(AtomicBool::new(false));
        let actor = PinnedActor {
            address: Cell::new(None),
            wake: wake.clone(),
            ready: ready.clone(),
            _pin: PhantomPinned,
        };
        let mut wrapped = Box::pin(observe(Role::Marshal, actor));
        require_send(&wrapped);
        assert!(
            wrapped
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        std::thread::spawn(move || {
            ready.store(true, Ordering::Release);
            wake.lock().as_ref().unwrap().wake_by_ref();
        })
        .join()
        .unwrap();
        assert_eq!(
            wrapped
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(23)
        );
    }
}
