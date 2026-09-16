use crate::types::Height;
use std::{collections::VecDeque, sync::Arc};

struct Entry<C, D, B> {
    commitment: C,
    digest: D,
    block: Arc<B>,
    bytes: usize,
    height: Height,
    finalized: bool,
}

/// FIFO cache for successfully decoded archive reads. Full commitments are
/// compared on commitment lookups, including variant-specific fields.
///
/// Encoded bytes are a retention weight, not a measurement of allocated heap.
/// Both the number of blocks and their total encoded size are bounded. Blocks
/// larger than the budget bypass the cache without evicting useful entries.
pub(super) struct DecodedBlocks<C, D, B> {
    entries: VecDeque<Entry<C, D, B>>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
}

impl<C: Eq, D: Eq, B> DecodedBlocks<C, D, B> {
    pub(super) const fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            max_entries,
            max_bytes,
        }
    }

    pub(super) fn by_commitment(&self, commitment: &C) -> Option<Arc<B>> {
        self.entries
            .iter()
            .find(|entry| &entry.commitment == commitment)
            .map(|entry| Arc::clone(&entry.block))
    }

    pub(super) fn by_digest(&self, digest: &D) -> Option<Arc<B>> {
        self.entries
            .iter()
            .find(|entry| &entry.digest == digest)
            .map(|entry| Arc::clone(&entry.block))
    }

    pub(super) fn by_height(&self, height: Height) -> Option<Arc<B>> {
        self.entries
            .iter()
            .find(|entry| entry.finalized && entry.height == height)
            .map(|entry| Arc::clone(&entry.block))
    }

    pub(super) fn prune(&mut self, height: Option<Height>) {
        self.entries
            .retain(|entry| height.map_or(entry.finalized, |height| entry.height >= height));
        self.bytes = self.entries.iter().map(|entry| entry.bytes).sum();
    }

    pub(super) fn insert(
        &mut self,
        commitment: C,
        digest: D,
        block: Arc<B>,
        bytes: usize,
        height: Height,
        finalized: bool,
    ) {
        if self.max_entries == 0 || bytes > self.max_bytes {
            return;
        }
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.commitment == commitment)
        {
            entry.finalized |= finalized;
            return;
        }
        while self.entries.len() >= self.max_entries || bytes > self.max_bytes - self.bytes {
            let entry = self
                .entries
                .pop_front()
                .expect("cache budget requires eviction");
            self.bytes -= entry.bytes;
        }
        self.entries.push_back(Entry {
            commitment,
            digest,
            block,
            bytes,
            height,
            finalized,
        });
        self.bytes += bytes;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoded_cache_matches_full_commitment_and_reuses_allocation() {
        let mut cache = DecodedBlocks::new(2, 100);
        let block = Arc::new(vec![1, 2, 3]);
        cache.insert((7, 1), 7, Arc::clone(&block), 3, Height::new(1), false);
        assert!(cache.by_commitment(&(7, 2)).is_none());
        assert!(cache.by_digest(&8).is_none());
        assert!(Arc::ptr_eq(&cache.by_commitment(&(7, 1)).unwrap(), &block));
        assert!(Arc::ptr_eq(&cache.by_digest(&7).unwrap(), &block));
    }

    #[test]
    fn decoded_cache_height_requires_archive_read_and_respects_pruning() {
        let mut cache = DecodedBlocks::new(3, 100);
        cache.insert(1, 1, Arc::new(1), 4, Height::new(1), false);
        assert!(cache.by_height(Height::new(1)).is_none());
        cache.insert(1, 1, Arc::new(1), 4, Height::new(1), true);
        cache.insert(2, 2, Arc::new(2), 4, Height::new(2), false);
        cache.insert(3, 3, Arc::new(3), 4, Height::new(3), true);
        assert!(cache.by_height(Height::new(1)).is_some());
        cache.prune(None);
        assert!(cache.by_digest(&2).is_none());
        assert_eq!(cache.bytes, 8);
        cache.prune(Some(Height::new(3)));
        assert!(cache.by_digest(&1).is_none());
        assert!(cache.by_height(Height::new(3)).is_some());
        assert_eq!(cache.bytes, 4);
    }

    #[test]
    fn decoded_cache_bounds_count_bytes_and_oversized_entries() {
        let mut cache = DecodedBlocks::new(2, 10);
        let first = Arc::new(1);
        cache.insert(1, 1, Arc::clone(&first), 4, Height::new(1), false);
        cache.insert(2, 2, Arc::new(2), 4, Height::new(1), false);
        cache.insert(3, 3, Arc::new(3), 4, Height::new(1), false);
        assert!(cache.by_commitment(&1).is_none());
        assert_eq!(Arc::strong_count(&first), 1);
        cache.insert(4, 4, Arc::new(4), 7, Height::new(1), false);
        assert!(cache.by_digest(&2).is_none());
        assert!(cache.by_digest(&3).is_none());
        assert_eq!(cache.bytes, 7);
        cache.insert(5, 5, Arc::new(5), 11, Height::new(1), false);
        assert!(cache.by_digest(&5).is_none());
        assert!(cache.by_digest(&4).is_some());
        // Duplicate reads do not accumulate references or charge bytes twice.
        cache.insert(4, 4, Arc::new(4), 7, Height::new(1), false);
        assert_eq!(cache.bytes, 7);
        assert_eq!(cache.entries.len(), 1);
    }
}
