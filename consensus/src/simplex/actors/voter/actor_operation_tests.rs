use super::voter_operation;
use futures::{channel::oneshot, executor::block_on, future, task::noop_waker};
use std::{future::Future, sync::Arc, task::Context};
use commonware_utils::sync::Mutex;
use tracing::{field::{Field, Visit}, span::Id, Event, Subscriber};
use tracing_subscriber::{layer::Context as LayerContext, prelude::*, registry::LookupSpan, Layer};

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<(String, String)>>>);
impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Events {
    fn on_event(&self, event: &Event<'_>, ctx: LayerContext<'_, S>) {
        struct Stage(Option<String>);
        impl Visit for Stage {
            fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
            fn record_str(&mut self, field: &Field, value: &str) {
                if field.name() == "stage" { self.0 = Some(value.to_owned()); }
            }
        }
        let mut stage = Stage(None);
        event.record(&mut stage);
        if let Some(stage) = stage.0 {
            let parent = ctx.event_span(event);
            self.0.lock().push((
                parent.as_ref().map_or("unbound", |span| span.name()).to_owned(), stage,
            ));
        }
    }
    fn on_close(&self, id: Id, ctx: LayerContext<'_, S>) {
        self.0.lock().push((ctx.span(&id).unwrap().name().to_owned(), "closed".into()));
    }
}

#[test]
fn completed_voter_operation_precedes_retained_child_close() {
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    tracing::subscriber::with_default(subscriber, || {
        let retained = Arc::new(Mutex::new(None));
        let child = retained.clone();
        let (tx, rx) = oneshot::channel::<u32>();
        let mut operation = Box::pin(voter_operation(tracing::info_span!("simplex.voter.notify"), async move {
            *child.lock() = Some(tracing::info_span!("retained_child"));
            rx.await.unwrap()
        }));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(operation.as_mut().poll(&mut cx).is_pending());
        assert!(events.0.lock().is_empty());
        tx.send(7).unwrap();
        assert_eq!(block_on(operation), 7);
        assert_eq!(*events.0.lock(), [("simplex.voter.notify".into(), "operation_completed".into())]);
        drop(retained.lock().take());
        assert_eq!(events.0.lock().last().unwrap(), &("simplex.voter.notify".into(), "closed".into()));
    });
}

#[test]
fn abandoned_voter_operation_precedes_retained_child_close() {
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    tracing::subscriber::with_default(subscriber, || {
        let retained = Arc::new(Mutex::new(None));
        let child = retained.clone();
        let mut operation = Box::pin(voter_operation(tracing::info_span!("simplex.voter.construct"), async move {
            *child.lock() = Some(tracing::info_span!("retained_child"));
            future::pending::<()>().await
        }));
        let waker = noop_waker();
        assert!(operation.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        drop(operation);
        assert_eq!(*events.0.lock(), [("simplex.voter.construct".into(), "operation_abandoned".into())]);
        drop(retained.lock().take());
        assert_eq!(events.0.lock().last().unwrap(), &("simplex.voter.construct".into(), "closed".into()));
    });
}

#[test]
fn disabled_voter_scope_cannot_complete_or_abandon_enabled_ancestor() {
    let events = Events::default();
    let subscriber = tracing_subscriber::registry()
        .with(events.clone())
        .with(tracing_subscriber::filter::filter_fn(|meta| meta.name() != "filtered_child"));
    tracing::subscriber::with_default(subscriber, || {
        let ancestor = tracing::info_span!("enabled_ancestor");
        ancestor.in_scope(|| {
            let child = tracing::debug_span!("filtered_child");
            assert!(child.is_disabled());
            assert_eq!(block_on(voter_operation(child, async { 7 })), 7);
            let mut pending = Box::pin(voter_operation(tracing::debug_span!("filtered_child"), future::pending::<()>()));
            let waker = noop_waker();
            assert!(pending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
            drop(pending);
        });
        assert!(events.0.lock().is_empty());
        drop(ancestor);
        assert_eq!(*events.0.lock(), [("enabled_ancestor".into(), "closed".into())]);
    });
}

#[test]
fn synchronous_publication_finishes_in_its_first_poll() {
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    tracing::subscriber::with_default(subscriber, || {
        let mut published = false;
        let mut operation = Box::pin(voter_operation(tracing::debug_span!("simplex.voter.publish"), async {
            published = true;
        }));
        let waker = noop_waker();
        assert!(operation.as_mut().poll(&mut Context::from_waker(&waker)).is_ready());
        drop(operation);
        assert!(published);
        assert_eq!(events.0.lock()[0], ("simplex.voter.publish".into(), "operation_completed".into()));
    });
}

#[test]
fn filtered_collector_never_rebinds_explicit_completion_to_ancestor() {
    let events = Events::default();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::sink))
        .with(events.clone().with_filter(tracing_subscriber::filter::filter_fn(
            |meta| meta.name() != "collector_filtered_child",
        )));
    tracing::subscriber::with_default(subscriber, || {
        let ancestor = tracing::info_span!("retained_collector_ancestor");
        ancestor.in_scope(|| {
            let child = tracing::debug_span!("collector_filtered_child");
            assert!(!child.is_disabled(), "formatting layer keeps the child globally enabled");
            block_on(voter_operation(child, async {}));
            let mut pending = Box::pin(voter_operation(
                tracing::debug_span!("collector_filtered_child"), future::pending::<()>(),
            ));
            let waker = noop_waker();
            assert!(pending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
            drop(pending);
        });
        // Same explicit-parent lookup as LifecycleLayer: filtered parent yields
        // None (collector ID 0), never the retained enabled ancestor. Milestone
        // capture additionally excludes these operation stages before lookup.
        assert_eq!(*events.0.lock(), [
            ("unbound".into(), "operation_completed".into()),
            ("unbound".into(), "operation_abandoned".into()),
        ]);
        drop(ancestor);
        assert_eq!(events.0.lock().last().unwrap(),
                   &("retained_collector_ancestor".into(), "closed".into()));
    });
}

#[test]
fn operation_wrapper_does_not_duplicate_large_future_state() {
    use tracing::Instrument as _;
    async fn previous_wrapper<F: Future>(span: tracing::Span, future: F) -> F::Output {
        if span.is_disabled() {
            future.await
        } else {
            commonware_utils::futures::lifecycle_operation(future).instrument(span).await
        }
    }
    let subscriber = tracing_subscriber::registry().with(Events::default());
    tracing::subscriber::with_default(subscriber, || {
        let current = voter_operation(tracing::info_span!("current"), future::ready([0u8; 16384]));
        let previous = previous_wrapper(tracing::info_span!("previous"), future::ready([0u8; 16384]));
        let current_bytes = std::mem::size_of_val(&current);
        let previous_bytes = std::mem::size_of_val(&previous);
        assert!(current_bytes + 16384 <= previous_bytes,
                "current {current_bytes}, previous {previous_bytes}");
    });
}
