//! Feature-only selected-task observer implementation.
use super::Role;
use crate::sync::Mutex;
use pin_project::{pin_project, pinned_drop};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};
const RETAINED_LIMIT: usize = 256;
static ENABLED: OnceLock<bool> = OnceLock::new();
static ACCOUNTING: OnceLock<Arc<Accounting>> = OnceLock::new();
pub(super) fn observe<F: Future>(role: Role, future: F) -> impl Future<Output = F::Output> {
    if !*ENABLED.get_or_init(|| {
        std::env::var("TEMPO_LIFECYCLE_ASYNC_TASKS").as_deref() == Ok("selected_v1")
    }) {
        return Capture::Disabled(future);
    }
    let accounting = ACCOUNTING
        .get_or_init(|| Arc::new(Accounting::new(RETAINED_LIMIT)))
        .clone();
    let sink = Sink::Trace(tracing::dispatcher::get_default(Clone::clone));
    capture(role, future, accounting, sink)
}
struct Accounting {
    retained: AtomicUsize,
    next: AtomicU64,
    limit: usize,
}
impl Accounting {
    const fn new(limit: usize) -> Self {
        Self {
            retained: AtomicUsize::new(0),
            next: AtomicU64::new(1),
            limit,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Record {
    Register(u64, u64),
    Wake(u64, u64),
    Begin(u64, u64, u64),
    End(u64, u64, u64),
    Terminal(u64, u64),
    Coverage(u64),
}

enum Sink {
    Trace(tracing::Dispatch),
    #[cfg(test)]
    Test(Arc<dyn Fn(Record) + Send + Sync>),
}
impl Sink {
    fn emit(&self, record: Record) {
        match self {
            Self::Trace(dispatch) => tracing::dispatcher::with_default(dispatch, || match record {
                Record::Register(task_id, task_role) => {
                    tracing::info!(target: "lifecycle", parent: None, stage="async_task_register", task_id, task_role)
                }
                Record::Wake(task_id, task_poll) => {
                    tracing::info!(target: "lifecycle", parent: None, stage="async_task_wake", task_id, task_poll)
                }
                Record::Begin(task_id, task_poll, task_wakes) => {
                    tracing::info!(target: "lifecycle", parent: None, stage="async_task_poll_begin", task_id, task_poll, task_wakes)
                }
                Record::End(task_id, task_poll, task_outcome) => {
                    tracing::info!(target: "lifecycle", parent: None, stage="async_task_poll_end", task_id, task_poll, task_outcome)
                }
                Record::Terminal(task_id, task_outcome) => {
                    tracing::info!(target: "lifecycle", parent: None, stage="async_task_terminal", task_id, task_outcome)
                }
                Record::Coverage(task_outcome) => {
                    tracing::info!(target: "lifecycle", parent: None, stage="async_task_coverage", task_outcome)
                }
            }),
            #[cfg(test)]
            Self::Test(callback) => callback(record),
        }
    }
}

#[pin_project(project = CaptureProj)]
enum Capture<F> {
    Disabled(#[pin] F),
    Enabled(#[pin] Observed<F>),
}
impl<F: Future> Future for Capture<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            CaptureProj::Disabled(future) => future.poll(cx),
            CaptureProj::Enabled(future) => future.poll(cx),
        }
    }
}

fn capture<F>(role: Role, future: F, accounting: Arc<Accounting>, sink: Sink) -> Capture<F> {
    if accounting
        .retained
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < accounting.limit).then_some(n + 1)
        })
        .is_err()
    {
        sink.emit(Record::Coverage(3));
        return Capture::Disabled(future);
    }
    let Ok(task) = accounting
        .next
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
    else {
        accounting.retained.fetch_sub(1, Ordering::Release);
        sink.emit(Record::Coverage(4));
        return Capture::Disabled(future);
    };
    let shared = Arc::new(Shared {
        task,
        accounting,
        sink,
        state: Mutex::new(State {
            upstream: None,
            poll: 0,
            wakes: 0,
            done: false,
        }),
    });
    shared.sink.emit(Record::Register(task, role as u64));
    Capture::Enabled(Observed { future, shared })
}

struct State {
    upstream: Option<Arc<Waker>>,
    poll: u64,
    wakes: u64,
    done: bool,
}
struct Shared {
    task: u64,
    accounting: Arc<Accounting>,
    sink: Sink,
    state: Mutex<State>,
}
impl Drop for Shared {
    fn drop(&mut self) {
        self.accounting.retained.fetch_sub(1, Ordering::Release);
    }
}
impl Wake for Shared {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let (upstream, first, poll, overflow) = {
            let mut state = self.state.lock();
            if state.done {
                return;
            }
            let first = state.wakes == 0;
            let overflow = state.wakes == u64::MAX || state.poll == u64::MAX;
            state.wakes = state.wakes.saturating_add(1);
            (
                state.upstream.clone(),
                first,
                state.poll.saturating_add(1),
                overflow,
            )
        };
        // Foreign callbacks and tracing subscribers never execute under our mutex.
        if overflow {
            self.sink.emit(Record::Coverage(6));
        }
        if first {
            self.sink.emit(Record::Wake(self.task, poll));
        }
        if let Some(upstream) = upstream {
            upstream.wake_by_ref();
        }
    }
}

#[pin_project(PinnedDrop)]
struct Observed<F> {
    #[pin]
    future: F,
    shared: Arc<Shared>,
}
impl<F: Future> Future for Observed<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let proxy = Waker::from(this.shared.clone());
        assert!(
            !cx.waker().will_wake(&proxy),
            "observer proxy cannot be its own upstream"
        );
        let replace = {
            let state = this.shared.state.lock();
            assert!(!state.done, "completed task polled again");
            state
                .upstream
                .as_ref()
                .is_none_or(|old| !old.will_wake(cx.waker()))
        };
        if replace {
            let replacement = Arc::new(cx.waker().clone());
            let retired = this.shared.state.lock().upstream.replace(replacement);
            drop(retired);
        }
        let (poll, wakes, overflow) = {
            let mut state = this.shared.state.lock();
            let overflow = state.poll == u64::MAX;
            state.poll = state.poll.saturating_add(1);
            (state.poll, std::mem::take(&mut state.wakes), overflow)
        };
        if overflow {
            this.shared.sink.emit(Record::Coverage(5));
        }
        let mut guard = PollGuard {
            shared: this.shared.clone(),
            poll,
            ended: false,
        };
        this.shared
            .sink
            .emit(Record::Begin(this.shared.task, poll, wakes));
        let result = this.future.poll(&mut Context::from_waker(&proxy));
        guard.end(if result.is_ready() { 1 } else { 0 });
        result
    }
}
#[pinned_drop]
impl<F> PinnedDrop for Observed<F> {
    fn drop(self: Pin<&mut Self>) {
        self.project().shared.finish(2);
    }
}
impl Shared {
    fn finish(&self, outcome: u64) {
        let retired = {
            let mut state = self.state.lock();
            if state.done {
                return;
            }
            state.done = true;
            state.upstream.take()
        };
        self.sink.emit(Record::Terminal(self.task, outcome));
        drop(retired);
    }
}
struct PollGuard {
    shared: Arc<Shared>,
    poll: u64,
    ended: bool,
}
impl PollGuard {
    fn end(&mut self, outcome: u64) {
        self.ended = true;
        self.shared
            .sink
            .emit(Record::End(self.shared.task, self.poll, outcome));
        if outcome != 0 {
            self.shared.finish(outcome);
        }
    }
}
impl Drop for PollGuard {
    fn drop(&mut self) {
        if !self.ended {
            self.end(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::Mutex;
    use futures::future::poll_fn;
    use std::sync::Barrier;

    type Records = Arc<Mutex<Vec<Record>>>;
    fn setup(limit: usize) -> (Arc<Accounting>, Records, Sink) {
        let records = Arc::new(Mutex::new(Vec::new()));
        let saved = records.clone();
        (
            Arc::new(Accounting::new(limit)),
            records,
            Sink::Test(Arc::new(move |record| saved.lock().push(record))),
        )
    }
    #[derive(Default)]
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn counter() -> (Arc<Counter>, Waker) {
        let counter = Arc::new(Counter::default());
        (counter.clone(), Waker::from(counter))
    }
    fn pending(saved: Arc<Mutex<Option<Waker>>>) -> impl Future<Output = ()> {
        poll_fn(move |cx| {
            *saved.lock() = Some(cx.waker().clone());
            Poll::Pending
        })
    }

    #[test]
    fn lifecycle_task_wakes_coalesce_without_coalescing_notifications() {
        let (accounting, records, sink) = setup(256);
        let saved = Arc::new(Mutex::new(None));
        let mut future = Box::pin(capture(
            Role::Voter,
            pending(saved.clone()),
            accounting.clone(),
            sink,
        ));
        let (counter, waker) = counter();
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let proxy = saved.lock().clone().unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let proxy = proxy.clone();
                scope.spawn(move || {
                    for _ in 0..1000 {
                        proxy.wake_by_ref();
                    }
                });
            }
        });
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert_eq!(counter.0.load(Ordering::SeqCst), 8000);
        assert_eq!(
            records
                .lock()
                .iter()
                .filter(|record| matches!(record, Record::Wake(1, 2)))
                .count(),
            1
        );
        assert!(records.lock().contains(&Record::Begin(1, 2, 8000)));
        drop(future);
        assert_eq!(accounting.retained.load(Ordering::Acquire), 1);
        drop(proxy);
        *saved.lock() = None;
        assert_eq!(accounting.retained.load(Ordering::Acquire), 0);
    }

    #[test]
    fn lifecycle_task_late_wake_emission_is_explicitly_ambiguous() {
        let (accounting, records, _) = setup(256);
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let sink = Sink::Test(Arc::new({
            let entered = entered.clone();
            let release = release.clone();
            let records = records.clone();
            move |record| {
                if matches!(record, Record::Wake(1, 2)) {
                    entered.wait();
                    release.wait();
                }
                records.lock().push(record);
            }
        }));
        let saved = Arc::new(Mutex::new(None));
        let mut future = Box::pin(capture(
            Role::Marshal,
            pending(saved.clone()),
            accounting,
            sink,
        ));
        let (_, waker) = counter();
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let proxy = saved.lock().clone().unwrap();
        std::thread::scope(|scope| {
            scope.spawn(move || proxy.wake());
            entered.wait();
            // A prior executor notification can allow polling before this wake is emitted.
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            release.wait();
        });
        let records = records.lock();
        let begin = records
            .iter()
            .position(|record| *record == Record::Begin(1, 2, 1))
            .unwrap();
        let wake = records
            .iter()
            .position(|record| *record == Record::Wake(1, 2))
            .unwrap();
        assert!(
            begin < wake,
            "consumer must reject an exact wait for this generation"
        );
    }

    #[test]
    fn lifecycle_task_self_wake_and_spurious_polls_remain_distinct() {
        let (accounting, records, sink) = setup(256);
        let mut calls = 0;
        let future = poll_fn(move |cx| {
            calls += 1;
            if calls == 1 {
                cx.waker().wake_by_ref();
            }
            if calls == 3 {
                Poll::Ready(7)
            } else {
                Poll::Pending
            }
        });
        let mut future = Box::pin(capture(Role::Resolver, future, accounting, sink));
        let (_, waker) = counter();
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert_eq!(
            future.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Ready(7)
        );
        let rows = records.lock();
        assert!(rows.contains(&Record::Begin(1, 1, 0)));
        assert!(rows.contains(&Record::Begin(1, 2, 1)));
        assert!(rows.contains(&Record::Begin(1, 3, 0)));
        let wake = rows
            .iter()
            .position(|record| *record == Record::Wake(1, 2))
            .unwrap();
        let end = rows
            .iter()
            .position(|record| *record == Record::End(1, 1, 0))
            .unwrap();
        assert!(
            wake < end,
            "wake during poll must not be counted as all waiting"
        );
    }

    #[test]
    fn lifecycle_task_cap_counts_stale_wakers_and_returns_original_future() {
        let (accounting, records, sink) = setup(1);
        let saved = Arc::new(Mutex::new(None));
        let mut future = Box::pin(capture(
            Role::PeerSend,
            pending(saved.clone()),
            accounting.clone(),
            sink,
        ));
        let (_, waker) = counter();
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(future);
        let rows = records.clone();
        let sink = Sink::Test(Arc::new(move |record| rows.lock().push(record)));
        let future = capture(
            Role::PeerReceive,
            std::future::ready(9),
            accounting.clone(),
            sink,
        );
        assert!(matches!(&future, Capture::Disabled(_)));
        assert_eq!(futures::executor::block_on(future), 9);
        assert!(records.lock().contains(&Record::Coverage(3)));
        *saved.lock() = None;
        assert_eq!(accounting.retained.load(Ordering::Acquire), 0);
    }

    #[test]
    fn lifecycle_task_ready_cancel_unpolled_and_panic_end_once() {
        for outcome in 0..4 {
            let (accounting, records, sink) = setup(256);
            let mut future = Box::pin(capture(
                Role::Batcher,
                poll_fn(move |_| {
                    assert_ne!(outcome, 3, "synthetic panic");
                    if outcome == 1 {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                }),
                accounting.clone(),
                sink,
            ));
            let (_, waker) = counter();
            if outcome != 2 {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    future.as_mut().poll(&mut Context::from_waker(&waker))
                }));
                assert_eq!(result.is_err(), outcome == 3);
            }
            drop(future);
            let rows = records.lock();
            assert_eq!(
                rows.iter()
                    .filter(|record| matches!(record, Record::Terminal(..)))
                    .count(),
                1
            );
            assert_eq!(
                rows.iter()
                    .filter(|record| matches!(record, Record::End(..)))
                    .count(),
                usize::from(outcome != 2)
            );
            assert_eq!(accounting.retained.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn lifecycle_task_disabled_forwards_original_context_and_pin() {
        let (_, waker) = counter();
        let mut cx = Context::from_waker(&waker);
        let expected = (&mut cx as *mut Context<'_>).cast::<()>();
        let future = poll_fn(move |actual| {
            assert!(
                (actual as *mut Context<'_>).cast::<()>() == expected,
                "poll context changed"
            );
            Poll::Ready(5)
        });
        assert_eq!(
            Box::pin(Capture::Disabled(future)).as_mut().poll(&mut cx),
            Poll::Ready(5)
        );
    }

    #[test]
    fn lifecycle_task_replacement_and_callbacks_do_not_hold_state_lock() {
        struct Reentrant {
            shared: Arc<Shared>,
            calls: AtomicUsize,
        }
        impl Wake for Reentrant {
            fn wake(self: Arc<Self>) {
                assert!(self.shared.state.try_lock().is_some());
                self.calls.fetch_add(1, Ordering::SeqCst);
            }
        }
        impl Drop for Reentrant {
            fn drop(&mut self) {
                assert!(self.shared.state.try_lock().is_some());
            }
        }
        let (accounting, records, sink) = setup(256);
        let saved = Arc::new(Mutex::new(None));
        let mut future = Box::pin(capture(
            Role::Marshal,
            pending(saved.clone()),
            accounting.clone(),
            sink,
        ));
        let Capture::Enabled(ref observed) = *future else {
            unreachable!()
        };
        let shared = observed.shared.clone();
        let upstream = Arc::new(Reentrant {
            shared: shared.clone(),
            calls: AtomicUsize::new(0),
        });
        let waker = Waker::from(upstream.clone());
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let proxy = saved.lock().clone().unwrap();
        proxy.wake_by_ref();
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
        let (_, replacement) = counter();
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&replacement))
                .is_pending()
        );
        proxy.wake_by_ref();
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
        drop(future);
        drop(waker);
        drop(upstream);
        drop(shared);
        drop(proxy);
        *saved.lock() = None;
        assert_eq!(accounting.retained.load(Ordering::Acquire), 0);
        assert_eq!(
            records
                .lock()
                .iter()
                .filter(|record| matches!(record, Record::Terminal(..)))
                .count(),
            1
        );
    }
    struct ReentrantRaw {
        shared: std::sync::Weak<Shared>,
        clones: AtomicUsize,
        wakes: AtomicUsize,
        drops: AtomicUsize,
        active: std::sync::atomic::AtomicBool,
    }
    impl ReentrantRaw {
        fn callback(&self, counter: &AtomicUsize) {
            counter.fetch_add(1, Ordering::SeqCst);
            if let Some(shared) = self.shared.upgrade() {
                assert!(
                    shared.state.try_lock().is_some(),
                    "foreign callback under state lock"
                );
                if !self.active.swap(true, Ordering::SeqCst) {
                    shared.wake_by_ref();
                    self.active.store(false, Ordering::SeqCst);
                }
            }
        }
    }
    unsafe fn raw_clone(data: *const ()) -> std::task::RawWaker {
        // SAFETY: Each vtable pointer owns one Arc count; cloning borrows that count
        // without consuming it and returns exactly one additional count.
        let state =
            std::mem::ManuallyDrop::new(unsafe { Arc::<ReentrantRaw>::from_raw(data.cast()) });
        state.callback(&state.clones);
        raw(Arc::clone(&state))
    }
    unsafe fn raw_wake(data: *const ()) {
        // SAFETY: wake consumes exactly the count owned by this RawWaker.
        let state = unsafe { Arc::<ReentrantRaw>::from_raw(data.cast()) };
        state.callback(&state.wakes);
    }
    unsafe fn raw_wake_ref(data: *const ()) {
        // SAFETY: wake_by_ref borrows the owned count without consuming it.
        let state =
            std::mem::ManuallyDrop::new(unsafe { Arc::<ReentrantRaw>::from_raw(data.cast()) });
        state.callback(&state.wakes);
    }
    unsafe fn raw_drop(data: *const ()) {
        // SAFETY: drop consumes exactly the count owned by this RawWaker.
        let state = unsafe { Arc::<ReentrantRaw>::from_raw(data.cast()) };
        state.callback(&state.drops);
    }
    static VTABLE: std::task::RawWakerVTable =
        std::task::RawWakerVTable::new(raw_clone, raw_wake, raw_wake_ref, raw_drop);
    fn raw(state: Arc<ReentrantRaw>) -> std::task::RawWaker {
        std::task::RawWaker::new(Arc::into_raw(state).cast(), &VTABLE)
    }
    fn reentrant_raw(shared: &Arc<Shared>) -> (Arc<ReentrantRaw>, Waker) {
        let state = Arc::new(ReentrantRaw {
            shared: Arc::downgrade(shared),
            clones: 0.into(),
            wakes: 0.into(),
            drops: 0.into(),
            active: false.into(),
        });
        // SAFETY: Vtable operations above preserve Arc ownership and are thread-safe.
        let waker = unsafe { Waker::from_raw(raw(state.clone())) };
        (state, waker)
    }

    #[test]
    fn lifecycle_task_foreign_raw_waker_callbacks_reenter_safely() {
        let (accounting, records, sink) = setup(256);
        let saved = Arc::new(Mutex::new(None));
        let mut future = Box::pin(capture(
            Role::Marshal,
            pending(saved.clone()),
            accounting.clone(),
            sink,
        ));
        let Capture::Enabled(ref observed) = *future else {
            unreachable!()
        };
        let shared = observed.shared.clone();
        let (old, old_waker) = reentrant_raw(&shared);
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&old_waker))
                .is_pending()
        );
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&old_waker))
                .is_pending()
        );
        saved.lock().as_ref().unwrap().wake_by_ref();
        assert_eq!(old.clones.load(Ordering::SeqCst), 1);
        let (new, new_waker) = reentrant_raw(&shared);
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&new_waker))
                .is_pending()
        );
        assert_eq!(old.drops.load(Ordering::SeqCst), 1);
        drop(future);
        assert_eq!(new.drops.load(Ordering::SeqCst), 1);
        *saved.lock() = None;
        drop(shared);
        drop(old_waker);
        drop(new_waker);
        assert_eq!(accounting.retained.load(Ordering::Acquire), 0);
        assert_eq!(
            records
                .lock()
                .iter()
                .filter(|record| matches!(record, Record::Terminal(..)))
                .count(),
            1
        );
    }

    #[test]
    fn lifecycle_task_late_wake_after_terminal_does_not_reopen_task() {
        let (accounting, records, _) = setup(256);
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let sink = Sink::Test(Arc::new({
            let entered = entered.clone();
            let release = release.clone();
            let records = records.clone();
            move |record| {
                if matches!(record, Record::Wake(1, 2)) {
                    entered.wait();
                    release.wait();
                }
                records.lock().push(record);
            }
        }));
        let saved = Arc::new(Mutex::new(None));
        let saved_future = saved.clone();
        let mut calls = 0;
        let inner = poll_fn(move |cx| {
            *saved_future.lock() = Some(cx.waker().clone());
            calls += 1;
            if calls == 2 {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        });
        let mut future = Box::pin(capture(Role::Marshal, inner, accounting, sink));
        let (_, waker) = counter();
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let proxy = saved.lock().clone().unwrap();
        std::thread::scope(|scope| {
            scope.spawn(move || proxy.wake());
            entered.wait();
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_ready()
            );
            release.wait();
        });
        let rows = records.lock();
        let end = rows
            .iter()
            .position(|record| *record == Record::Terminal(1, 1))
            .unwrap();
        let wake = rows
            .iter()
            .position(|record| *record == Record::Wake(1, 2))
            .unwrap();
        assert!(end < wake);
        assert_eq!(
            rows.iter()
                .filter(|record| matches!(record, Record::Terminal(..)))
                .count(),
            1
        );
    }
    #[test]
    fn lifecycle_task_counter_exhaustion_fails_coverage_without_losing_work() {
        let (accounting, records, sink) = setup(256);
        accounting.next.store(u64::MAX, Ordering::Relaxed);
        let future = capture(
            Role::Marshal,
            std::future::ready(19),
            accounting.clone(),
            sink,
        );
        assert_eq!(futures::executor::block_on(future), 19);
        assert_eq!(*records.lock(), vec![Record::Coverage(4)]);
        assert_eq!(accounting.retained.load(Ordering::Acquire), 0);
        let (accounting, records, sink) = setup(256);
        let saved = Arc::new(Mutex::new(None));
        let mut future = Box::pin(capture(
            Role::Voter,
            pending(saved.clone()),
            accounting,
            sink,
        ));
        let (counter, waker) = counter();
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let Capture::Enabled(ref observed) = *future else {
            unreachable!()
        };
        {
            let mut state = observed.shared.state.lock();
            state.poll = u64::MAX;
            state.wakes = u64::MAX;
        }
        saved.lock().as_ref().unwrap().wake_by_ref();
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let records = records.lock();
        assert!(records.contains(&Record::Coverage(5)));
        assert!(records.contains(&Record::Coverage(6)));
    }

    #[test]
    fn lifecycle_task_trace_dispatch_and_fields_survive_foreign_thread_wake() {
        use tracing_subscriber::{Layer, layer::SubscriberExt};
        type TraceRow = (String, std::collections::BTreeMap<String, u64>);
        struct Events(Arc<Mutex<Vec<TraceRow>>>);
        #[derive(Default)]
        struct Fields {
            stage: String,
            numeric: std::collections::BTreeMap<String, u64>,
        }
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                assert_eq!(field.name(), "stage");
                self.stage = value.into();
            }
            fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                assert!(
                    [
                        "task_id",
                        "task_role",
                        "task_poll",
                        "task_wakes",
                        "task_outcome"
                    ]
                    .contains(&field.name())
                );
                self.numeric.insert(field.name().into(), value);
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {
                panic!("non-allowlisted trace field");
            }
        }
        impl<S: tracing::Subscriber> Layer<S> for Events {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                assert_eq!(event.metadata().target(), "lifecycle");
                assert!(event.is_root());
                let mut fields = Fields::default();
                event.record(&mut fields);
                self.0.lock().push((fields.stage, fields.numeric));
            }
        }
        let events = Arc::new(Mutex::new(Vec::new()));
        let saved = Arc::new(Mutex::new(None));
        let mut future = Box::pin(tracing::subscriber::with_default(
            tracing_subscriber::registry().with(Events(events.clone())),
            || {
                let sink = Sink::Trace(tracing::dispatcher::get_default(Clone::clone));
                capture(
                    Role::Marshal,
                    pending(saved.clone()),
                    Arc::new(Accounting::new(256)),
                    sink,
                )
            },
        ));
        let (_, waker) = counter();
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let proxy = saved.lock().clone().unwrap();
        std::thread::spawn(move || proxy.wake()).join().unwrap();
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(future);
        let events = events.lock();
        assert!(
            events
                .iter()
                .any(|(stage, fields)| stage == "async_task_wake"
                    && fields["task_id"] == 1
                    && fields["task_poll"] == 2)
        );
        assert_eq!(
            events
                .iter()
                .filter(|(stage, _)| stage == "async_task_terminal")
                .count(),
            1
        );
        assert_eq!(events[0].1["task_role"], Role::Marshal as u64);
    }
}
