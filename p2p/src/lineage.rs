//! Private submission markers; ordinals never enter encoded messages.
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_QUEUE_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn queue_start(
    stage: &'static str,
    message_id: Option<u64>,
    receive_id: Option<u64>,
) -> Option<u64> {
    if (message_id.is_none() && receive_id.is_none())
        || !tracing::enabled!(target: "lifecycle", tracing::Level::INFO)
    {
        return None;
    }
    let queue_id = NEXT_QUEUE_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .ok()?;
    tracing::info!(target: "lifecycle", stage, queue_id, message_id = message_id.unwrap_or(0), receive_id = receive_id.unwrap_or(0));
    Some(queue_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[commonware_macros::test_traced]
    fn queue_lineage_distinguishes_fanout_and_disabled_capture() {
        let first = queue_start("message_peer_queue_start", Some(7), None).unwrap();
        let second = queue_start("message_peer_queue_start", Some(7), None).unwrap();
        let received = queue_start("message_inbound_queue_start", None, Some(7)).unwrap();
        assert_ne!(first, 0);
        assert_ne!(first, second);
        assert_ne!(second, received);
        assert_eq!(queue_start("message_peer_queue_start", None, None), None);
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
            assert_eq!(queue_start("message_peer_queue_start", Some(7), None), None);
        });
    }
}
