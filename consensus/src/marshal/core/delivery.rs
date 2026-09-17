use super::Variant;
use crate::simplex::{
    scheme::Scheme,
    types::{Finalization, Notarization},
};
use bytes::Bytes;
use commonware_codec::Error;
use commonware_cryptography::certificate::{Scheme as CertificateScheme, Scoped};
use commonware_utils::channel::oneshot;
use std::sync::Arc;

/// Reuse a structurally validated block only when its complete canonical wire
/// encoding matches the received bytes. The caller must select the cached block
/// by full commitment under the same codec configuration and still verify the
/// certificate. Every other response follows the normal decoder, including
/// malformed, alternate, and trailing-byte encodings.
pub(super) fn decode_cached_delivery<B: crate::Block + Clone>(
    value: Bytes,
    cfg: &B::Cfg,
    cached: Option<Arc<B>>,
) -> Result<B, Error> {
    if let Some(block) = cached
        && block.can_reuse_cached_encoding(cfg)
        && block.encode_size() == value.len()
        && block.encode().as_ref() == value.as_ref()
    {
        return tracing::debug_span!(target: "lifecycle", "marshal.reuse_delivered_block", block_hash = %block.digest())
            .in_scope(|| Ok(Arc::unwrap_or_clone(block)));
    }
    B::decode_cfg(value, cfg)
}

/// A parsed-but-unverified resolver delivery awaiting batch certificate verification.
///
/// Each item carries the scope it was admitted under so verification does not
/// depend on the provider still serving that epoch.
pub(super) enum PendingVerification<S: CertificateScheme, V: Variant>
where
    S: Scheme<V::Commitment>,
{
    Notarized {
        scoped: Scoped<S>,
        notarization: Notarization<S, V::Commitment>,
        block: V::Block,
        response: oneshot::Sender<bool>,
    },
    Finalized {
        scoped: Scoped<S>,
        finalization: Finalization<S, V::Commitment>,
        block: V::ApplicationBlock,
        response: oneshot::Sender<bool>,
    },
}

impl<S: CertificateScheme, V: Variant> PendingVerification<S, V>
where
    S: Scheme<V::Commitment>,
{
    /// Returns the scope the delivery was admitted under.
    pub(super) const fn scoped(&self) -> &Scoped<S> {
        match self {
            Self::Notarized { scoped, .. } | Self::Finalized { scoped, .. } => scoped,
        }
    }

    pub(super) fn response_closed(&self) -> bool {
        match self {
            Self::Notarized { response, .. } | Self::Finalized { response, .. } => {
                response.is_closed()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{marshal::core::decoded::DecodedBlocks, types::Height};
    use bytes::{Buf, BufMut};
    use commonware_codec::{Decode, Encode, EncodeSize, Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn reuse_scope_identifies_exact_block_without_parent() {
        use commonware_cryptography::Digestible as _;
        use commonware_utils::sync::Mutex;
        use tracing_subscriber::{layer::SubscriberExt as _, Layer};
        struct Capture(Arc<Mutex<Vec<String>>>);
        impl<S: tracing::Subscriber> Layer<S> for Capture {
            fn on_new_span(&self, attrs: &tracing::span::Attributes<'_>, _: &tracing::span::Id,
                _: tracing_subscriber::layer::Context<'_, S>) {
                if attrs.metadata().name() != "marshal.reuse_delivered_block" { return; }
                struct Fields<'a>(&'a mut Vec<String>);
                impl tracing::field::Visit for Fields<'_> {
                    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                        if field.name() == "block_hash" { self.0.push(format!("{value:?}")); }
                    }
                }
                attrs.record(&mut Fields(&mut self.0.lock()));
            }
        }
        let block = TestBlock([42, 1, 2, 3, 4, 5, 6, 7]);
        let expected = block.digest().to_string();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Capture(observed.clone()));
        tracing::subscriber::with_default(subscriber, || {
            assert_eq!(decode_cached_delivery(block.encode(), &Arc::new(AtomicUsize::new(0)),
                Some(Arc::new(block.clone()))).unwrap(), block);
        });
        assert_eq!(*observed.lock(), vec![expected]);
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestBlock([u8; 8]);

    impl Write for TestBlock {
        fn write(&self, buf: &mut impl BufMut) {
            buf.put_slice(&self.0);
        }
    }

    impl EncodeSize for TestBlock {
        fn encode_size(&self) -> usize {
            self.0.len()
        }
    }

    impl Read for TestBlock {
        type Cfg = Arc<AtomicUsize>;

        fn read_cfg(buf: &mut impl Buf, reads: &Self::Cfg) -> Result<Self, Error> {
            reads.fetch_add(1, Ordering::Relaxed);
            let bytes = <[u8; 8]>::read_cfg(buf, &())?;
            if bytes[0] != 42 {
                return Err(Error::Invalid("test block", "invalid tag"));
            }
            Ok(Self(bytes))
        }
    }

    impl commonware_cryptography::Digestible for TestBlock {
        type Digest = commonware_cryptography::sha256::Digest;

        fn digest(&self) -> Self::Digest {
            use commonware_cryptography::Hasher;
            commonware_cryptography::Sha256::hash(&[&self.0])
        }
    }

    impl crate::Heightable for TestBlock {
        fn height(&self) -> Height {
            Height::new(0)
        }
    }

    impl crate::Block for TestBlock {
        fn parent(&self) -> Self::Digest {
            commonware_cryptography::Digestible::digest(self)
        }

        fn can_reuse_cached_encoding(&self, _cfg: &Self::Cfg) -> bool {
            self.0[0] == 42
        }
    }

    #[derive(Clone, Debug)]
    struct DefaultBlock(TestBlock);

    impl Write for DefaultBlock {
        fn write(&self, buf: &mut impl BufMut) {
            self.0.write(buf);
        }
    }

    impl EncodeSize for DefaultBlock {
        fn encode_size(&self) -> usize {
            self.0.encode_size()
        }
    }

    impl Read for DefaultBlock {
        type Cfg = u8;

        fn read_cfg(buf: &mut impl Buf, limit: &Self::Cfg) -> Result<Self, Error> {
            let bytes = <[u8; 8]>::read_cfg(buf, &())?;
            if bytes[0] > *limit {
                return Err(Error::Invalid("default block", "configuration limit"));
            }
            Ok(Self(TestBlock(bytes)))
        }
    }

    impl commonware_cryptography::Digestible for DefaultBlock {
        type Digest = commonware_cryptography::sha256::Digest;

        fn digest(&self) -> Self::Digest {
            use commonware_cryptography::Hasher;
            commonware_cryptography::Sha256::hash(&[&self.0.0])
        }
    }

    impl crate::Heightable for DefaultBlock {
        fn height(&self) -> Height {
            Height::new(0)
        }
    }

    impl crate::Block for DefaultBlock {
        fn parent(&self) -> Self::Digest {
            commonware_cryptography::Digestible::digest(self)
        }
    }

    #[test]
    fn cached_delivery_default_standard_preserves_config_rejection() {
        // The default Standard variant must not infer decoder validity from a
        // locally constructed object's identity conversions or matching bytes.
        type V = crate::marshal::standard::Standard<DefaultBlock>;
        let block = Arc::new(DefaultBlock(TestBlock([42; 8])));
        let cfg = V::block_cfg(&0, commonware_cryptography::Digestible::digest(&*block));
        assert!(DefaultBlock::decode_cfg(block.encode(), &cfg).is_err());
        assert!(decode_cached_delivery(block.encode(), &cfg, Some(block)).is_err());
    }

    #[test]
    fn cached_delivery_exact_bytes_reuse_without_decode() {
        let reads = Arc::new(AtomicUsize::new(0));
        let block = Arc::new(TestBlock([42, 1, 2, 3, 4, 5, 6, 7]));
        let encoded = block.encode();
        let decoded = decode_cached_delivery(encoded, &reads, Some(Arc::clone(&block))).unwrap();
        assert_eq!(&decoded, block.as_ref());
        assert_eq!(reads.load(Ordering::Relaxed), 0);
        assert_eq!(Arc::strong_count(&block), 1);
    }

    #[test]
    fn cached_delivery_misses_preserve_decoder_results() {
        let block = Arc::new(TestBlock([42, 1, 2, 3, 4, 5, 6, 7]));
        let mut inputs = vec![block.encode()];
        for index in 0..8 {
            let mut bytes = block.0;
            bytes[index] ^= 1;
            inputs.push(Bytes::copy_from_slice(&bytes));
        }
        for length in 0..8 {
            inputs.push(Bytes::copy_from_slice(&block.0[..length]));
        }
        let mut trailing = block.0.to_vec();
        trailing.push(0);
        inputs.push(trailing.into());
        for value in inputs {
            let reads = Arc::new(AtomicUsize::new(0));
            let expected =
                TestBlock::decode_cfg(value.clone(), &reads).map_err(|error| error.to_string());
            reads.store(0, Ordering::Relaxed);
            let actual = decode_cached_delivery(value.clone(), &reads, None::<Arc<TestBlock>>)
                .map_err(|error| error.to_string());
            assert_eq!(actual, expected);
            assert_eq!(reads.load(Ordering::Relaxed), 1);
            reads.store(0, Ordering::Relaxed);
            let actual = decode_cached_delivery(value.clone(), &reads, Some(Arc::clone(&block)))
                .map_err(|error| error.to_string());
            assert_eq!(actual, expected);
            assert_eq!(
                reads.load(Ordering::Relaxed),
                usize::from(value.as_ref() != block.0)
            );
        }
    }

    #[test]
    fn cached_delivery_requires_full_commitment_and_obeys_eviction() {
        let reads = Arc::new(AtomicUsize::new(0));
        let block = Arc::new(TestBlock([42, 1, 2, 3, 4, 5, 6, 7]));
        let mut cache = DecodedBlocks::new(1, 8);
        cache.insert((7, 1), 7, Arc::clone(&block), 8, Height::new(1), false);
        // An aliased digest with a different full commitment is a cache miss.
        decode_cached_delivery(block.encode(), &reads, cache.by_commitment(&(7, 2))).unwrap();
        assert_eq!(reads.load(Ordering::Relaxed), 1);
        decode_cached_delivery(block.encode(), &reads, cache.by_commitment(&(7, 1))).unwrap();
        assert_eq!(reads.load(Ordering::Relaxed), 1);
        cache.insert((8, 1), 8, Arc::clone(&block), 8, Height::new(2), false);
        decode_cached_delivery(block.encode(), &reads, cache.by_commitment(&(7, 1))).unwrap();
        assert_eq!(reads.load(Ordering::Relaxed), 2);
        cache.prune(Some(Height::new(3)));
        decode_cached_delivery(block.encode(), &reads, cache.by_commitment(&(8, 1))).unwrap();
        assert_eq!(reads.load(Ordering::Relaxed), 3);
    }
}
