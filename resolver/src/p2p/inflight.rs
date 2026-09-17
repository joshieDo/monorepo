use crate::{
    Consumer, Delivery, Outcome,
    delivery::{Completion, Tracker},
};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, telemetry::metrics::histogram};
use futures::future::Aborted;
use std::time::Duration;

/// Tracks all in-flight fetch state.
pub(super) struct Inflight<Con, P>
where
    Con: Consumer<Value = Bytes>,
    P: PublicKey,
{
    /// Resolver-agnostic delivery state shared with non-P2P resolver implementations.
    deliveries: Tracker<Con, (P, Duration, usize, Option<u64>), histogram::Timer>,
}

impl<Con, P> Inflight<Con, P>
where
    Con: Consumer<Value = Bytes>,
    P: PublicKey,
{
    pub(super) fn new(consumer: Con) -> Self {
        Self {
            deliveries: Tracker::new(consumer),
        }
    }

    /// Returns true if there is an in-flight entry for the key.
    pub(super) fn contains(&self, key: &Con::Key) -> bool {
        self.deliveries.contains(key)
    }

    /// Insert a new in-flight entry for the key.
    pub(super) fn insert(&mut self, key: Con::Key, timer: histogram::Timer) {
        assert!(
            self.deliveries.insert_with_state(key, timer),
            "inflight entry"
        );
    }

    /// Remove the in-flight entry for the key and cancel its duration timer (suppressing
    /// the recording). If delivery validation was in progress, it is aborted and any
    /// invalid result is discarded. Returns true if an entry was present.
    pub(super) fn cancel(&mut self, key: &Con::Key) -> bool {
        self.deliveries.remove(key)
    }

    /// Mark the in-flight entry for the key as complete, recording its duration.
    /// Panics if no entry exists for the key.
    pub(super) fn complete<E: Clock>(&mut self, clock: &E, key: &Con::Key) {
        if let Some(timer) = self
            .deliveries
            .remove_with_state(key)
            .expect("inflight entry")
        {
            timer.observe(clock);
        }
    }

    /// Drop entries for which the predicate returns false. Returns the count of dropped entries.
    pub(super) fn retain<F: FnMut(&Con::Key) -> bool>(&mut self, predicate: F) -> usize {
        self.deliveries.retain(predicate)
    }

    /// Drop all entries. Returns the count of dropped entries.
    pub(super) fn drain(&mut self) -> usize {
        self.deliveries.drain()
    }

    /// Begin a consumer delivery for a network response, attaching the abort handle.
    /// Spawns `consumer.deliver(delivery, value)` as an in-flight future and records
    /// the response so later subscribers can be delivered the same bytes.
    pub(super) fn deliver(
        &mut self,
        delivery: Delivery<Con::Key, Con::Subscriber>,
        peer: P,
        elapsed: Duration,
        value: Con::Value,
        receive_id: Option<u64>,
    ) {
        let delivery = response_context(delivery, receive_id);
        self.deliveries
            .deliver(delivery, (peer, elapsed, value.len(), receive_id), value);
    }

    /// Begin another consumer delivery for an already received response.
    pub(super) fn redeliver(&mut self, delivery: Delivery<Con::Key, Con::Subscriber>) {
        let receive_id = self
            .deliveries
            .response_context(&delivery.key)
            .and_then(|context| context.3);
        self.deliveries
            .redeliver(response_context(delivery, receive_id));
    }

    /// Returns whether the current response has already been accepted by the consumer.
    pub(super) fn response_accepted(&self, key: &Con::Key) -> bool {
        self.deliveries.response_accepted(key)
    }

    /// Mark the current response accepted and record the fetch duration.
    pub(super) fn accept_response<E: Clock>(&mut self, key: &Con::Key, clock: &E) {
        self.deliveries.accept_response(key);
        if let Some(timer) = self.deliveries.take_state(key) {
            timer.observe(clock);
        }
    }

    /// Drop the current response without completing the fetch.
    pub(super) fn discard_response(&mut self, key: &Con::Key) {
        self.deliveries.discard_response(key);
    }

    /// Returns the next completed delivery, or [Aborted] if it was canceled.
    /// Clears the entry's delivery aborter so the slot is available for a retry.
    /// The outcome is `None` if the consumer dropped its verdict.
    pub(super) async fn next_delivery(
        &mut self,
    ) -> Result<
        (
            P,
            Duration,
            usize,
            Delivery<Con::Key, Con::Subscriber>,
            Option<Outcome>,
        ),
        Aborted,
    > {
        let Completion {
            context,
            delivery,
            outcome,
        } = self.deliveries.next_completion().await?;
        Ok((context.0, context.1, context.2, delivery, outcome))
    }
}

/// Preserve request ancestry while attaching the exact response to each subscriber.
/// These spans describe retained context, not service or queue duration.
fn response_context<K, S>(mut delivery: Delivery<K, S>, receive_id: Option<u64>) -> Delivery<K, S> {
    if let Some(receive_id) = receive_id.filter(|id| *id != 0) {
        for (_, request) in delivery.subscribers.iter_mut() {
            let context = tracing::debug_span!(target: "lifecycle", parent: &*request, "resolver.response.context", receive_id);
            if !context.is_disabled() {
                *request = context;
            }
        }
    }
    delivery
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::mocks::{Consumer as MockConsumer, Key as MockKey};
    use bytes::Bytes;
    use commonware_cryptography::{
        Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{
        Metrics, Runner as _,
        deterministic::{Context, Runner},
        telemetry::metrics::{MetricsExt, histogram::Buckets},
    };
    use commonware_utils::non_empty_vec;

    type TestInflight = Inflight<MockConsumer<MockKey, Bytes>, PublicKey>;

    fn dummy_inflight() -> TestInflight {
        Inflight::new(MockConsumer::dummy())
    }

    fn make_timed(context: &Context) -> histogram::Timed {
        let registered = context.histogram("test_duration", "Test histogram", Buckets::LOCAL);
        histogram::Timed::new(registered)
    }

    fn pubkey() -> PublicKey {
        PrivateKey::from_seed(0).public_key()
    }

    fn delivery(key: MockKey) -> Delivery<MockKey, ()> {
        Delivery {
            key,
            subscribers: non_empty_vec![((), tracing::Span::none())],
        }
    }

    #[test]
    fn response_lineage_follows_cached_bytes_across_redelivery_and_replacement() {
        use commonware_utils::sync::Mutex;
        use std::sync::Arc;
        use tracing::{
            Subscriber,
            field::{Field, Visit},
            span::{Attributes, Id},
        };
        use tracing_subscriber::{
            Layer,
            layer::{Context as LayerContext, SubscriberExt},
        };
        type CapturedContexts = Vec<(u64, Option<u64>)>;
        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<CapturedContexts>>);
        struct Ordinal(Option<u64>);
        impl Visit for Ordinal {
            fn record_debug(&mut self, _: &Field, _: &dyn core::fmt::Debug) {}
            fn record_u64(&mut self, field: &Field, value: u64) {
                if field.name() == "receive_id" {
                    self.0 = Some(value);
                }
            }
        }
        impl<S: Subscriber> Layer<S> for Capture {
            fn on_new_span(&self, attrs: &Attributes<'_>, _: &Id, _: LayerContext<'_, S>) {
                if attrs.metadata().name() != "resolver.response.context" {
                    return;
                }
                let mut ordinal = Ordinal(None);
                attrs.record(&mut ordinal);
                self.0
                    .lock()
                    .push((ordinal.0.unwrap(), attrs.parent().map(Id::into_u64)));
            }
        }
        let capture = Capture::default();
        tracing::subscriber::with_default(
            tracing_subscriber::registry().with(capture.clone()),
            || {
                Runner::default().start(|context| async move {
                    let timed = make_timed(&context);
                    let (consumer, mut received) = MockConsumer::<MockKey, Bytes>::new();
                    let mut inflight: TestInflight = Inflight::new(consumer);
                    let key = MockKey(1);
                    inflight.insert(key.clone(), timed.timer(&context));
                    let request = tracing::debug_span!("request");
                    let parent_id = request.id().unwrap().into_u64();
                    let make_delivery = || Delivery {
                        key: key.clone(),
                        subscribers: non_empty_vec![((), request.clone())],
                    };
                    inflight.deliver(
                        make_delivery(),
                        pubkey(),
                        Duration::ZERO,
                        Bytes::from("first"),
                        Some(11),
                    );
                    assert_eq!(
                        inflight.next_delivery().await.unwrap().4,
                        Some(Outcome::Complete)
                    );
                    assert_eq!(received.recv().await.unwrap().1, Bytes::from("first"));
                    inflight.accept_response(&key, &context);
                    // A newly supplied subscriber gets the original response's ordinal.
                    inflight.redeliver(make_delivery());
                    assert_eq!(
                        inflight.next_delivery().await.unwrap().4,
                        Some(Outcome::Complete)
                    );
                    assert_eq!(received.recv().await.unwrap().1, Bytes::from("first"));
                    inflight.discard_response(&key);
                    assert!(inflight.deliveries.response_context(&key).is_none());
                    inflight.deliver(
                        make_delivery(),
                        pubkey(),
                        Duration::ZERO,
                        Bytes::from("second"),
                        Some(22),
                    );
                    assert_eq!(
                        inflight.next_delivery().await.unwrap().4,
                        Some(Outcome::Complete)
                    );
                    assert_eq!(received.recv().await.unwrap().1, Bytes::from("second"));
                    assert_eq!(
                        *capture.0.lock(),
                        [
                            (11, Some(parent_id)),
                            (11, Some(parent_id)),
                            (22, Some(parent_id))
                        ]
                    );
                    assert!(inflight.cancel(&key));
                    assert!(inflight.deliveries.response_context(&key).is_none());
                    // Absent and zero metadata leave existing ancestry unchanged.
                    for receive_id in [None, Some(0)] {
                        let delivered = response_context(make_delivery(), receive_id);
                        assert_eq!(delivered.subscribers.first().1.id(), request.id());
                    }
                });
            },
        );
    }

    #[test]
    fn filtered_response_context_preserves_request_span() {
        use tracing_subscriber::{Layer, layer::SubscriberExt};
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::sink)
            .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                meta.name() != "resolver.response.context"
            }));
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
            let request = tracing::debug_span!("request");
            assert!(request.id().is_some());
            let delivery = Delivery {
                key: MockKey(1),
                subscribers: non_empty_vec![((), request.clone())],
            };
            let delivered = response_context(delivery, Some(11));
            assert_eq!(delivered.subscribers.first().1.id(), request.id());
        });
    }

    #[test]
    fn test_insert_contains_cancel_remove_round_trip() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = dummy_inflight();

            assert!(!inflight.contains(&MockKey(1)));
            inflight.insert(MockKey(1), timed.timer(&context));
            assert!(inflight.contains(&MockKey(1)));

            assert!(inflight.cancel(&MockKey(1)));
            assert!(!inflight.contains(&MockKey(1)));

            // Subsequent cancel of an absent key returns false.
            assert!(!inflight.cancel(&MockKey(1)));
        });
    }

    #[test]
    fn test_cancel_suppresses_duration_metric() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = dummy_inflight();

            inflight.insert(MockKey(1), timed.timer(&context));
            inflight.cancel(&MockKey(1));

            let metrics = context.encode();
            assert!(metrics.contains("test_duration_count 0"));
        });
    }

    #[test]
    fn test_complete_records_duration_metric() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = dummy_inflight();

            inflight.insert(MockKey(1), timed.timer(&context));
            inflight.complete(&context, &MockKey(1));

            let metrics = context.encode();
            assert!(metrics.contains("test_duration_count 1"));
        });
    }

    #[test]
    #[should_panic(expected = "inflight entry")]
    fn test_complete_panics_on_missing_key() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut inflight: TestInflight = dummy_inflight();
            inflight.complete(&context, &MockKey(1));
        });
    }

    #[test]
    fn test_retain_drops_non_matching_and_suppresses_metric() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = dummy_inflight();

            inflight.insert(MockKey(1), timed.timer(&context));
            inflight.insert(MockKey(2), timed.timer(&context));
            inflight.insert(MockKey(3), timed.timer(&context));

            let dropped = inflight.retain(|k| k.0 % 2 == 1);
            assert_eq!(dropped, 1);
            assert!(inflight.contains(&MockKey(1)));
            assert!(!inflight.contains(&MockKey(2)));
            assert!(inflight.contains(&MockKey(3)));

            let metrics = context.encode();
            assert!(metrics.contains("test_duration_count 0"));
        });
    }

    #[test]
    fn test_drain_removes_all_and_suppresses_metric() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = dummy_inflight();

            inflight.insert(MockKey(1), timed.timer(&context));
            inflight.insert(MockKey(2), timed.timer(&context));

            assert_eq!(inflight.drain(), 2);
            assert!(!inflight.contains(&MockKey(1)));
            assert!(!inflight.contains(&MockKey(2)));

            let metrics = context.encode();
            assert!(metrics.contains("test_duration_count 0"));
        });
    }

    #[test]
    fn test_deliver_completes_with_consumer_result() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let (consumer, mut events) = MockConsumer::<MockKey, Bytes>::new();
            let mut inflight: TestInflight = Inflight::new(consumer);
            let peer = pubkey();
            let key = MockKey(7);
            let value = Bytes::from("data");

            inflight.insert(key.clone(), timed.timer(&context));
            inflight.deliver(
                delivery(key.clone()),
                peer.clone(),
                Duration::from_millis(17),
                value.clone(),
                None,
            );

            let (delivered_peer, elapsed, bytes, delivered, outcome) =
                inflight.next_delivery().await.expect("delivery aborted");
            assert_eq!(delivered.key, key);
            assert_eq!(delivered_peer, peer);
            assert_eq!(elapsed, Duration::from_millis(17));
            assert_eq!(bytes, value.len());
            assert_eq!(outcome, Some(Outcome::Complete));

            // The consumer was actually invoked.
            let (k, v) = events.recv().await.unwrap();
            assert_eq!(k, key);
            assert_eq!(v, value);
        });
    }

    #[test]
    fn test_deliver_aborts_when_entry_dropped_before_poll() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let mut inflight: TestInflight = Inflight::new(consumer);
            let peer = pubkey();
            let key = MockKey(1);

            inflight.insert(key.clone(), timed.timer(&context));
            inflight.deliver(
                delivery(key.clone()),
                peer,
                Duration::ZERO,
                Bytes::from("v"),
                None,
            );

            // Drop the entry (and its aborter) before the delivery future is ever polled.
            assert!(inflight.cancel(&key));

            let result = inflight.next_delivery().await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_cancel_after_completion_is_idempotent() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let mut inflight: TestInflight = Inflight::new(consumer);
            let peer = pubkey();
            let key = MockKey(1);

            inflight.insert(key.clone(), timed.timer(&context));
            inflight.deliver(
                delivery(key.clone()),
                peer,
                Duration::ZERO,
                Bytes::from("v"),
                None,
            );

            let (_, _, _, delivered, outcome) =
                inflight.next_delivery().await.expect("delivery completed");
            assert_eq!(delivered.key, key);
            assert_eq!(outcome, Some(Outcome::Complete));
            inflight.complete(&context, &key);

            // Late cancel finds no entry; must not panic.
            assert!(!inflight.cancel(&key));
        });
    }

    #[test]
    fn test_cancel_wins_race_with_completion() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let mut inflight: TestInflight = Inflight::new(consumer);
            let peer = pubkey();
            let key = MockKey(1);

            inflight.insert(key.clone(), timed.timer(&context));
            inflight.deliver(
                delivery(key.clone()),
                peer,
                Duration::ZERO,
                Bytes::from("v"),
                None,
            );

            // Cancel before any poll of the pool: drops the Aborter, removes the entry.
            assert!(inflight.cancel(&key));

            // Subsequent poll must yield Err (cancel won the race), not Ok.
            let result = inflight.next_delivery().await;
            assert!(matches!(result, Err(Aborted)));
        });
    }

    #[test]
    fn test_drain_aborts_in_flight_deliveries() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let mut inflight: TestInflight = Inflight::new(consumer);
            let peer = pubkey();
            let key = MockKey(1);

            inflight.insert(key.clone(), timed.timer(&context));
            inflight.deliver(delivery(key), peer, Duration::ZERO, Bytes::from("v"), None);

            assert_eq!(inflight.drain(), 1);

            let result = inflight.next_delivery().await;
            assert!(result.is_err());
        });
    }
}
