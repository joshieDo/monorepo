//! Codec wrapper for [Sender] and [Receiver].

use crate::{Blocker, CheckedSender, Receiver, Recipients, Sender};
use commonware_actor::{Feedback, Unreliable, mailbox};
use commonware_codec::{Codec, Error};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPool, ContextCell, Handle, Metrics, Spawner, iobuf::EncodeExt, spawn_cell,
};
use commonware_utils::futures::Pool;
use std::{collections::VecDeque, num::NonZeroUsize, time::SystemTime};

/// Wrap a [Sender] and [Receiver] with some [Codec].
pub const fn wrap<S: Sender, R: Receiver, V: Codec>(
    config: V::Cfg,
    pool: BufferPool,
    sender: S,
    receiver: R,
) -> (WrappedSender<S, V>, WrappedReceiver<R, V>) {
    (
        WrappedSender::new(pool, sender),
        WrappedReceiver::new(config, receiver),
    )
}

/// Tuple representing a message received from a given public key.
pub type WrappedMessage<P, V> = (P, Result<V, Error>);

/// Wrapper around a [Sender] that encodes messages using a [Codec].
#[derive(Clone)]
pub struct WrappedSender<S: Sender, V: Codec> {
    pool: BufferPool,
    sender: S,
    _phantom_v: std::marker::PhantomData<V>,
}

impl<S: Sender, V: Codec> WrappedSender<S, V> {
    /// Create a new [WrappedSender] with the given [Sender] and [BufferPool] for encoding.
    pub const fn new(pool: BufferPool, sender: S) -> Self {
        Self {
            pool,
            sender,
            _phantom_v: std::marker::PhantomData,
        }
    }

    /// Send a message to a set of recipients.
    pub fn send(
        &mut self,
        recipients: Recipients<S::PublicKey>,
        message: V,
        priority: bool,
    ) -> Vec<S::PublicKey> {
        self.send_ref(recipients, &message, priority)
    }

    /// Send a borrowed message to a set of recipients.
    #[tracing::instrument(
        name = "network.codec.send_ref",
        target = "lifecycle",
        level = "debug",
        skip_all
    )]
    pub fn send_ref(
        &mut self,
        recipients: Recipients<S::PublicKey>,
        message: &V,
        priority: bool,
    ) -> Vec<S::PublicKey> {
        let encoded = message.encode_with_pool(&self.pool);
        self.sender.send(recipients, encoded, priority)
    }

    /// Check if a message can be sent to a set of recipients, returning a [CheckedWrappedSender]
    /// or the time at which the send can be retried.
    pub fn check(
        &mut self,
        recipients: Recipients<S::PublicKey>,
    ) -> Result<CheckedWrappedSender<'_, S, V>, SystemTime> {
        self.sender
            .check(recipients)
            .map(|checked| CheckedWrappedSender {
                pool: &self.pool,
                sender: checked,
                _phantom_v: std::marker::PhantomData,
            })
    }
}

/// Checked sender that wraps a [`crate::LimitedSender::Checked`] and encodes messages using a [Codec].
#[derive(Debug)]
pub struct CheckedWrappedSender<'a, S: Sender, V: Codec> {
    pool: &'a BufferPool,
    sender: S::Checked<'a>,
    _phantom_v: std::marker::PhantomData<V>,
}

impl<'a, S: Sender, V: Codec> CheckedWrappedSender<'a, S, V> {
    pub fn recipients(&self) -> Vec<S::PublicKey> {
        self.sender.recipients()
    }

    pub fn send(self, message: V, priority: bool) -> Unreliable<Feedback> {
        self.send_ref(&message, priority)
    }

    #[tracing::instrument(
        name = "network.codec.send_ref",
        target = "lifecycle",
        level = "debug",
        skip_all
    )]
    pub fn send_ref(self, message: &V, priority: bool) -> Unreliable<Feedback> {
        let encoded = message.encode_with_pool(self.pool);
        self.sender.send(encoded, priority)
    }
}

/// Wrapper around a [Receiver] that decodes messages using a [Codec].
pub struct WrappedReceiver<R: Receiver, V: Codec> {
    config: V::Cfg,
    receiver: R,
}

impl<R: Receiver, V: Codec> WrappedReceiver<R, V> {
    /// Create a new [WrappedReceiver] with the given [Receiver].
    pub const fn new(config: V::Cfg, receiver: R) -> Self {
        Self { config, receiver }
    }

    /// Receive a message from an arbitrary recipient.
    #[tracing::instrument(
        name = "network.codec.recv",
        target = "lifecycle",
        level = "debug",
        skip_all
    )]
    pub async fn recv(&mut self) -> Result<WrappedMessage<R::PublicKey, V>, R::Error> {
        let ((pk, bytes), receive_id) = self.receiver.recv_with_context().await?;
        if let Some(receive_id) = receive_id {
            tracing::info!(target: "lifecycle", stage = "message_decode", receive_id);
        }
        let result = V::decode_cfg(bytes.as_ref(), &self.config);
        if let Some(receive_id) = receive_id {
            tracing::info!(target: "lifecycle", stage = "message_decode_result", receive_id, accepted = u64::from(result.is_ok()));
        }
        let decoded = match result {
            Ok(decoded) => decoded,
            Err(e) => {
                return Ok((pk, Err(e)));
            }
        };
        Ok((pk, Ok(decoded)))
    }
}

/// A background receiver that receives raw bytes from a [`Receiver`] and spawns concurrent
/// decode tasks using a [`Codec`].
///
/// Decode work is submitted to the provided [`Strategy`], so callers can offload expensive
/// decodes from the receive loop by choosing a parallel strategy.
///
/// The receiver bounds in-flight decode jobs to the strategy's manual parallelism hint before
/// reading more bytes. Successfully decoded messages are forwarded through a bounded mailbox; if
/// the consumer falls behind and the mailbox fills, additional decoded messages are dropped (they
/// would likely no longer be useful by the time we get back to them).
struct Decoded<P: PublicKey, V>(P, V, Option<u64>);

impl<P: PublicKey, V> mailbox::UnreliablePolicy for Decoded<P, V> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
        false
    }
}

/// Receiver half for successfully decoded messages from a [`WrappedBackgroundReceiver`].
pub struct BackgroundReceiver<P: PublicKey, V> {
    receiver: mailbox::UnreliableReceiver<Decoded<P, V>>,
}

impl<P: PublicKey, V> BackgroundReceiver<P, V> {
    /// Receive the next successfully decoded message.
    #[tracing::instrument(
        name = "network.codec.recv",
        target = "lifecycle",
        level = "debug",
        skip_all
    )]
    pub async fn recv(&mut self) -> Option<(P, V)> {
        self.receiver
            .recv()
            .await
            .map(|Decoded(peer, value, receive_id)| {
                if let Some(receive_id) = receive_id {
                    tracing::info!(target: "lifecycle", stage = "message_delivered", receive_id);
                }
                (peer, value)
            })
    }
}

pub struct WrappedBackgroundReceiver<E, P, B, R, V, T>
where
    E: Spawner,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
    R: Receiver<PublicKey = P>,
    V: Codec + Send,
    T: Strategy,
{
    context: ContextCell<E>,
    receiver: R,
    codec_config: V::Cfg,
    blocker: B,
    sender: mailbox::UnreliableSender<Decoded<P, V>>,
    strategy: T,
}

impl<E, P, B, R, V, T> WrappedBackgroundReceiver<E, P, B, R, V, T>
where
    E: Spawner + Metrics,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
    R: Receiver<PublicKey = P>,
    V: Codec + Send + 'static,
    T: Strategy,
{
    /// Create a new [`WrappedBackgroundReceiver`].
    ///
    /// `channel_capacity` controls the size of the internal channel to the consumer.
    pub fn new(
        context: E,
        receiver: R,
        codec_config: V::Cfg,
        blocker: B,
        channel_capacity: NonZeroUsize,
        strategy: T,
    ) -> (Self, BackgroundReceiver<P, V>) {
        let (tx, rx) = mailbox::new_unreliable(context.child("mailbox"), channel_capacity);
        (
            Self {
                context: ContextCell::new(context),
                receiver,
                codec_config,
                blocker,
                sender: tx,
                strategy,
            },
            BackgroundReceiver { receiver: rx },
        )
    }

    /// Start the background receiver.
    ///
    /// Returns a [`Handle`] that must be kept alive for the background receiver to continue
    /// running. Dropping the handle will abort the background receiver.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    /// Run the background receiver's event loop.
    ///
    /// Each incoming message is decoded via the provided strategy, up to the in-flight decode
    /// limit. With a multi-worker strategy this lets the receive loop continue draining the network
    /// buffer while decodes proceed on pool workers; inline strategies decode on the receive loop.
    async fn run(mut self) {
        let decode_queue_capacity = self.strategy.manual().parallelism();
        let mut decode_pool = Pool::default();
        let mut receiver_closed = false;

        select_loop! {
            self.context,
            on_start => {
                while decode_pool.len() >= decode_queue_capacity
                    || (receiver_closed && !decode_pool.is_empty())
                {
                    let result = decode_pool.next_completed().await;
                    Self::handle_decode_result(&mut self.blocker, &mut self.sender, result);
                }
                if receiver_closed && decode_pool.is_empty() {
                    break;
                }
            },
            on_stopped => {},
            // Process decode completions as they arrive
            result = decode_pool.next_completed() => {
                Self::handle_decode_result(&mut self.blocker, &mut self.sender, result);
            },
            // Receive raw bytes and submit decode work to the strategy.
            Ok(((peer, bytes), receive_id)) = self.receiver.recv_with_context() else {
                receiver_closed = true;
                continue;
            } => {
                let config = self.codec_config.clone();
                let handle = self.strategy.spawn(bytes.len(), move |_| {
                    let _decode = tracing::debug_span!(target: "lifecycle", "network.codec.decode", receive_id = receive_id.unwrap_or(0)).entered();
                    if let Some(receive_id) = receive_id {
                        tracing::info!(target: "lifecycle", stage = "message_decode", receive_id);
                    }
                    let result = V::decode_cfg(bytes.as_ref(), &config);
                    if let Some(receive_id) = receive_id {
                        tracing::info!(target: "lifecycle", stage = "message_decode_result", receive_id, accepted = u64::from(result.is_ok()));
                    }
                    (peer, result, receive_id)
                });
                decode_pool.push(handle);
            },
        }
    }

    fn handle_decode_result(
        blocker: &mut B,
        sender: &mut mailbox::UnreliableSender<Decoded<P, V>>,
        result: (P, Result<V, commonware_codec::Error>, Option<u64>),
    ) {
        let (peer, decode_result, receive_id) = result;
        match decode_result {
            Ok(value) => {
                let queue_id =
                    crate::lineage::queue_start("message_decoded_queue_start", None, receive_id);
                let feedback = sender.enqueue(Decoded(peer, value, receive_id));
                if let Some(receive_id) = receive_id {
                    tracing::info!(target: "lifecycle", stage = "message_decoded_queue", queue_id = queue_id.unwrap_or(0), receive_id, accepted = u64::from(feedback.accepted()));
                }
            }
            Err(err) => {
                crate::block!(blocker, peer, ?err, "received invalid message");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Manager as _, Recipients,
        simulated::{self, Link, Network, Oracle},
    };
    use commonware_actor::Feedback;
    use commonware_codec::Encode;
    use commonware_cryptography::{
        Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_macros::test_traced;
    use commonware_parallel::{Sequential, mocks};
    use commonware_runtime::{Clock as _, IoBuf, Quota, Runner, Supervisor as _, deterministic};
    use commonware_utils::{
        NZUsize,
        channel::{mpsc, ring},
        ordered::Set,
        probability,
    };
    use std::{
        io,
        num::NonZeroU32,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    const LINK: Link = Link {
        latency: Duration::from_millis(0),
        jitter: Duration::from_millis(0),
        success_rate: probability!(1.0),
    };

    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    fn start_network(context: deterministic::Context) -> Oracle<PublicKey, deterministic::Context> {
        let (network, oracle) = Network::new(
            context.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                max_peers_per_set: NZUsize!(3),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
        );
        network.start();
        oracle
    }

    fn pk(seed: u64) -> PublicKey {
        PrivateKey::from_seed(seed).public_key()
    }

    fn track_peers<I>(oracle: &Oracle<PublicKey, deterministic::Context>, index: u64, peers: I)
    where
        I: IntoIterator<Item = PublicKey>,
    {
        oracle.manager().track(index, Set::from_iter_dedup(peers));
    }

    async fn link_bidirectional(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        a: PublicKey,
        b: PublicKey,
    ) {
        oracle.add_link(a.clone(), b.clone(), LINK).await.unwrap();
        oracle.add_link(b, a, LINK).await.unwrap();
    }

    #[derive(Debug)]
    struct MockReceiver<P: commonware_cryptography::PublicKey> {
        receiver: mpsc::UnboundedReceiver<crate::Message<P>>,
    }

    impl<P: commonware_cryptography::PublicKey> crate::Receiver for MockReceiver<P> {
        type Error = io::Error;
        type PublicKey = P;

        #[tracing::instrument(
            name = "network.codec.recv",
            target = "lifecycle",
            level = "debug",
            skip_all
        )]
        async fn recv(&mut self) -> Result<crate::Message<Self::PublicKey>, Self::Error> {
            self.receiver
                .recv()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[derive(Debug)]
    struct CountingReceiver<P: commonware_cryptography::PublicKey> {
        receiver: mpsc::UnboundedReceiver<crate::Message<P>>,
        received: Arc<AtomicUsize>,
    }

    impl<P: commonware_cryptography::PublicKey> crate::Receiver for CountingReceiver<P> {
        type Error = io::Error;
        type PublicKey = P;

        #[tracing::instrument(
            name = "network.codec.recv",
            target = "lifecycle",
            level = "debug",
            skip_all
        )]
        async fn recv(&mut self) -> Result<crate::Message<Self::PublicKey>, Self::Error> {
            self.received.fetch_add(1, Ordering::SeqCst);
            self.receiver
                .recv()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[derive(Clone, Default)]
    struct NoopBlocker;

    impl crate::Blocker for NoopBlocker {
        type PublicKey = PublicKey;

        fn block(&mut self, _peer: Self::PublicKey) -> Feedback {
            Feedback::Ok
        }

        fn blocked(&mut self) -> crate::BlockedSubscription<Self::PublicKey> {
            let (_, receiver) = ring::channel(NZUsize!(1));
            receiver
        }
    }

    #[test_traced]
    fn test_valid_messages_forwarded() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.child("network"));

            let pk1 = pk(0);
            let pk2 = pk(1);
            let control1 = oracle.control(pk1.clone());
            let control2 = oracle.control(pk2.clone());
            track_peers(&oracle, 0, [pk1.clone(), pk2.clone()]);
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            let (mut sender1, _) = control1.register(0, TEST_QUOTA).await.unwrap();
            let (_, receiver2) = control2.register(0, TEST_QUOTA).await.unwrap();

            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32, _>::new(
                context.child("bg"),
                receiver2,
                (),
                control2.clone(),
                NZUsize!(16),
                Sequential,
            );
            let _handle = bg.start();

            let msg: u32 = 42;
            let _ = sender1.send(Recipients::One(pk2.clone()), msg.encode(), true);

            let (from, value) = rx.recv().await.unwrap();
            assert_eq!(from, pk1);
            assert_eq!(value, 42u32);
        });
    }

    #[test_traced]
    fn test_invalid_codec_blocks_peer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.child("network"));

            let pk1 = pk(0);
            let pk2 = pk(1);
            let pk3 = pk(2);
            let control1 = oracle.control(pk1.clone());
            let control2 = oracle.control(pk2.clone());
            track_peers(&oracle, 0, [pk1.clone(), pk2.clone(), pk3.clone()]);
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            let (mut sender1, _) = control1.register(0, TEST_QUOTA).await.unwrap();
            let (_, receiver2) = control2.register(0, TEST_QUOTA).await.unwrap();

            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32, _>::new(
                context.child("bg"),
                receiver2,
                (),
                control2.clone(),
                NZUsize!(16),
                Sequential,
            );
            let _handle = bg.start();

            // Send a truncated payload (1 byte, but u32 needs 4).
            let invalid = IoBuf::from(vec![0xFFu8]);
            let _ = sender1.send(Recipients::One(pk2.clone()), invalid, true);

            // Then send a valid message from a different peer to confirm
            // the receiver is still running.
            let control3 = oracle.control(pk3.clone());
            link_bidirectional(&mut oracle, pk3.clone(), pk2.clone()).await;
            let (mut sender3, _) = control3.register(0, TEST_QUOTA).await.unwrap();

            let msg: u32 = 99;
            let _ = sender3.send(Recipients::One(pk2.clone()), msg.encode(), true);

            let (from, value) = rx.recv().await.unwrap();
            assert_eq!(from, pk3);
            assert_eq!(value, 99u32);

            // Verify pk1 was blocked.
            loop {
                let blocked = oracle.blocked().await.unwrap();
                if blocked.contains(&(pk2.clone(), pk1.clone())) {
                    break;
                }

                context.sleep(Duration::from_millis(1)).await;
            }
        });
    }

    #[test_traced]
    fn test_multiple_valid_messages() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.child("network"));

            let pk1 = pk(0);
            let pk2 = pk(1);
            let control1 = oracle.control(pk1.clone());
            let control2 = oracle.control(pk2.clone());
            track_peers(&oracle, 0, [pk1.clone(), pk2.clone()]);
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            let (mut sender1, _) = control1.register(0, TEST_QUOTA).await.unwrap();
            let (_, receiver2) = control2.register(0, TEST_QUOTA).await.unwrap();

            let count = 20;
            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32, _>::new(
                context.child("bg"),
                receiver2,
                (),
                control2.clone(),
                NZUsize!(20),
                Sequential,
            );
            let _handle = bg.start();

            for i in 0..count {
                let msg: u32 = i;
                let _ = sender1.send(Recipients::One(pk2.clone()), msg.encode(), true);
            }

            let mut received = Vec::new();
            for _ in 0..count {
                let (from, value) = rx.recv().await.unwrap();
                assert_eq!(from, pk1);
                received.push(value);
            }
            received.sort();
            assert_eq!(received, (0..count).collect::<Vec<u32>>());
        });
    }

    #[test_traced]
    fn test_decode_with_strategy() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.child("network"));

            let pk1 = pk(0);
            let pk2 = pk(1);
            let control1 = oracle.control(pk1.clone());
            let control2 = oracle.control(pk2.clone());
            track_peers(&oracle, 0, [pk1.clone(), pk2.clone()]);
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            let (mut sender1, _) = control1.register(0, TEST_QUOTA).await.unwrap();
            let (_, receiver2) = control2.register(0, TEST_QUOTA).await.unwrap();

            // Give the decoded mailbox enough capacity for all messages so this test only
            // exercises the decode concurrency bound.
            let count = 50u32;
            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32, _>::new(
                context.child("bg"),
                receiver2,
                (),
                control2.clone(),
                NZUsize!(50),
                mocks::inline(NZUsize!(4)),
            );
            let _handle = bg.start();

            for i in 0..count {
                let _ = sender1.send(Recipients::One(pk2.clone()), i.encode(), true);
            }

            let mut received = Vec::new();
            for _ in 0..count {
                let (from, value) = rx.recv().await.unwrap();
                assert_eq!(from, pk1);
                received.push(value);
            }
            received.sort();
            assert_eq!(received, (0..count).collect::<Vec<u32>>());
        });
    }

    #[test_traced]
    fn test_invalid_among_valid_only_blocks_offender() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.child("network"));

            let pk1 = pk(0);
            let pk2 = pk(1);
            let pk3 = pk(2);
            let control1 = oracle.control(pk1.clone());
            let control2 = oracle.control(pk2.clone());
            let control3 = oracle.control(pk3.clone());
            track_peers(&oracle, 0, [pk1.clone(), pk2.clone(), pk3.clone()]);
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;
            link_bidirectional(&mut oracle, pk3.clone(), pk2.clone()).await;

            let (mut sender1, _) = control1.register(0, TEST_QUOTA).await.unwrap();
            let (_, receiver2) = control2.register(0, TEST_QUOTA).await.unwrap();
            let (mut sender3, _) = control3.register(0, TEST_QUOTA).await.unwrap();

            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32, _>::new(
                context.child("bg"),
                receiver2,
                (),
                control2.clone(),
                NZUsize!(16),
                Sequential,
            );
            let _handle = bg.start();

            // pk3 sends valid message.
            let _ = sender3.send(Recipients::One(pk2.clone()), 10u32.encode(), true);

            // pk1 sends invalid message.
            let _ = sender1.send(Recipients::One(pk2.clone()), IoBuf::from(vec![0xFF]), true);

            // pk3 sends another valid message.
            let _ = sender3.send(Recipients::One(pk2.clone()), 20u32.encode(), true);

            // Collect the two valid messages.
            let mut values = Vec::new();
            for _ in 0..2 {
                let (from, value) = rx.recv().await.unwrap();
                assert_eq!(from, pk3);
                values.push(value);
            }
            values.sort();
            assert_eq!(values, vec![10u32, 20]);

            // Only pk1 should be blocked.
            loop {
                let blocked = oracle.blocked().await.unwrap();
                assert!(!blocked.contains(&(pk2.clone(), pk3.clone())));
                if blocked.contains(&(pk2.clone(), pk1.clone())) {
                    break;
                }

                context.sleep(Duration::from_millis(1)).await;
            }
        });
    }

    #[test_traced]
    fn test_decoded_messages_drop_when_receiver_full() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let sender = pk(0);
            let (tx, receiver) = mpsc::unbounded_channel();

            for i in 0..2u32 {
                tx.send((sender.clone(), IoBuf::from(i.encode())))
                    .expect("mock receiver should be open");
            }
            drop(tx);

            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32, _>::new(
                context.child("bg"),
                MockReceiver { receiver },
                (),
                NoopBlocker,
                NZUsize!(1),
                Sequential,
            );
            let handle = bg.start();
            handle.await.expect("background receiver should complete");

            let (from, value) = rx.recv().await.unwrap();
            assert_eq!(from, sender);
            assert_eq!(value, 0);
            assert!(rx.recv().await.is_none());
        });
    }

    #[test_traced]
    fn test_decode_backpressure_limits_raw_receives() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let sender = pk(0);
            let (tx, receiver) = mpsc::unbounded_channel();
            let received = Arc::new(AtomicUsize::new(0));

            for i in 0..10u32 {
                tx.send((sender.clone(), IoBuf::from(i.encode())))
                    .expect("mock receiver should be open");
            }

            let (bg, _rx) = WrappedBackgroundReceiver::<_, _, _, _, u32, _>::new(
                context.child("bg"),
                CountingReceiver {
                    receiver,
                    received: received.clone(),
                },
                (),
                NoopBlocker,
                NZUsize!(16),
                mocks::pending(NZUsize!(2)),
            );
            let handle = bg.start();

            while received.load(Ordering::SeqCst) < 2 {
                context.sleep(Duration::from_millis(1)).await;
            }
            for _ in 0..10 {
                context.sleep(Duration::from_millis(1)).await;
                assert_eq!(received.load(Ordering::SeqCst), 2);
            }

            drop(handle);
        });
    }

    #[test_traced]
    fn test_drain_decode_pool_after_receiver_closure() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let sender = pk(0);
            let (tx, receiver) = mpsc::unbounded_channel();
            let count = 64u32;

            for i in 0..count {
                tx.send((sender.clone(), IoBuf::from(i.encode())))
                    .expect("mock receiver should be open");
            }
            drop(tx);

            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32, _>::new(
                context.child("bg"),
                MockReceiver { receiver },
                (),
                NoopBlocker,
                NZUsize!(64),
                Sequential,
            );
            let _handle = bg.start();

            let mut values = Vec::new();
            while let Some((from, value)) = rx.recv().await {
                assert_eq!(from, sender);
                values.push(value);
            }
            values.sort_unstable();

            assert_eq!(values, (0..count).collect::<Vec<u32>>());
        });
    }
    #[derive(Debug)]
    struct ContextReceiver {
        receiver: mpsc::UnboundedReceiver<(crate::Message<PublicKey>, Option<u64>)>,
    }
    impl crate::Receiver for ContextReceiver {
        type Error = io::Error;
        type PublicKey = PublicKey;
        async fn recv(&mut self) -> Result<crate::Message<PublicKey>, io::Error> {
            self.recv_with_context().await.map(|(value, _)| value)
        }
        async fn recv_with_context(
            &mut self,
        ) -> Result<(crate::Message<PublicKey>, Option<u64>), io::Error> {
            self.receiver
                .recv()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn test_lineage_background_malformed_and_overflow_keep_payload_context() {
        deterministic::Runner::default().start(|context| async move {
            let peer = pk(0);
            let (tx, receiver) = mpsc::unbounded_channel();
            for (bytes, id) in [
                (IoBuf::from(1u32.encode()), 11),
                (IoBuf::from(b"bad"), 99),
                (IoBuf::from(2u32.encode()), 22),
                (IoBuf::from(3u32.encode()), 33),
            ] {
                tx.send(((peer.clone(), bytes), Some(id))).unwrap();
            }
            drop(tx);
            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32, _>::new(
                context.child("bg"),
                ContextReceiver { receiver },
                (),
                NoopBlocker,
                NZUsize!(2),
                Sequential,
            );
            bg.start().await.unwrap();
            for (expected, id) in [(1, 11), (2, 22)] {
                let Decoded(from, value, context) = rx.receiver.recv().await.unwrap();
                assert_eq!((from, value, context), (peer.clone(), expected, Some(id)));
            }
            assert!(rx.receiver.recv().await.is_none());
        });
    }

    #[test]
    fn test_lineage_reordered_results_and_rejection_do_not_swap_ids() {
        deterministic::Runner::default().start(|context| async move {
            let (mut tx, mut rx) = mailbox::new_unreliable(context.child("results"), NZUsize!(2));
            let mut blocker = NoopBlocker;
            type Decoder = WrappedBackgroundReceiver<
                deterministic::Context,
                PublicKey,
                NoopBlocker,
                ContextReceiver,
                u32,
                Sequential,
            >;
            // Completion order differs from submission order, with a malformed neighbor.
            Decoder::handle_decode_result(&mut blocker, &mut tx, (pk(0), Ok(20), Some(2)));
            Decoder::handle_decode_result(
                &mut blocker,
                &mut tx,
                (pk(0), Err(commonware_codec::Error::EndOfBuffer), Some(3)),
            );
            Decoder::handle_decode_result(&mut blocker, &mut tx, (pk(0), Ok(10), Some(1)));
            Decoder::handle_decode_result(&mut blocker, &mut tx, (pk(0), Ok(40), Some(4)));
            for (value, id) in [(20, 2), (10, 1)] {
                let Decoded(_, actual, context) = rx.recv().await.unwrap();
                assert_eq!((actual, context), (value, Some(id)));
            }
            assert!(rx.try_recv().is_err());
        });
    }

    #[test]
    fn test_lineage_default_receiver_and_cancelled_pending_decode() {
        deterministic::Runner::default().start(|context| async move {
            let (tx, receiver) = mpsc::unbounded_channel();
            tx.send((pk(0), IoBuf::from(7u32.encode()))).unwrap();
            let mut legacy = MockReceiver { receiver };
            let ((_, bytes), context_id) = legacy.recv_with_context().await.unwrap();
            assert_eq!(bytes, IoBuf::from(7u32.encode()));
            assert_eq!(context_id, None);
            let (tx, receiver) = mpsc::unbounded_channel();
            tx.send(((pk(0), IoBuf::from(8u32.encode())), Some(8)))
                .unwrap();
            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32, _>::new(
                context.child("pending"),
                ContextReceiver { receiver },
                (),
                NoopBlocker,
                NZUsize!(2),
                mocks::pending(NZUsize!(2)),
            );
            let handle = bg.start();
            context.sleep(Duration::from_millis(1)).await;
            assert!(rx.receiver.try_recv().is_err());
            drop(handle);
            context.sleep(Duration::from_millis(1)).await;
            assert!(
                rx.receiver.try_recv().is_err(),
                "cancelled jobs must not fabricate delivery"
            );
        });
    }
}
