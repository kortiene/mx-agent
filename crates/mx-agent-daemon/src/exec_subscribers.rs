//! In-memory forwarding registry for Matrix exec/call result events.
//!
//! The daemon owns Matrix `/sync`, credentials, signing keys, policy, and
//! process supervision. A CLI waiting on IPC must therefore subscribe to the
//! daemon for the invocation/request it started rather than syncing Matrix
//! itself. This module provides that bridge: routed Matrix stream/result events
//! are published to subscribers keyed by invocation id (exec/stream events) or
//! request id (`call.response`).
//!
//! The registry is deliberately in-memory. A disconnected CLI is removed and
//! misses future live stream events, which matches normal terminal stream
//! semantics and avoids persisting potentially sensitive output payloads.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use mx_agent_protocol::schema::{
    CallResponse, ExecCancelled, ExecFinished, ExecRejected, StreamArtifact, StreamChunk,
};

/// Key used to match a routed Matrix event to waiting IPC subscribers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum ExecSubscriptionKey {
    /// Events tied to an exec invocation id (`inv_...`).
    Invocation(String),
    /// Events tied to a request id (`req_...`), used by `call.response`.
    Request(String),
}

/// A Matrix stream/result event forwarded to a waiting IPC subscriber.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", content = "payload", rename_all = "snake_case")]
pub enum ForwardedExecEvent {
    /// A stdout/stderr chunk.
    StreamChunk(StreamChunk),
    /// An output artifact notification.
    StreamArtifact(StreamArtifact),
    /// A target daemon rejected an exec request.
    ExecRejected(ExecRejected),
    /// An exec invocation finished.
    ExecFinished(ExecFinished),
    /// An exec invocation was cancelled.
    ExecCancelled(ExecCancelled),
    /// A named-tool call response.
    CallResponse(CallResponse),
}

impl ForwardedExecEvent {
    /// Return the subscriber key this event should be delivered to.
    pub fn key(&self) -> ExecSubscriptionKey {
        match self {
            Self::StreamChunk(ev) => ExecSubscriptionKey::Invocation(ev.invocation_id.clone()),
            Self::StreamArtifact(ev) => ExecSubscriptionKey::Invocation(ev.invocation_id.clone()),
            Self::ExecRejected(ev) => ExecSubscriptionKey::Invocation(ev.invocation_id.clone()),
            Self::ExecFinished(ev) => ExecSubscriptionKey::Invocation(ev.invocation_id.clone()),
            Self::ExecCancelled(ev) => ExecSubscriptionKey::Invocation(ev.invocation_id.clone()),
            Self::CallResponse(ev) => ExecSubscriptionKey::Request(ev.request_id.clone()),
        }
    }
}

/// Result of publishing one event to the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ForwardStats {
    /// Number of subscribers that accepted the event.
    pub delivered: usize,
    /// Number of disconnected subscribers pruned while publishing.
    pub pruned: usize,
}

#[derive(Debug)]
struct Subscriber {
    id: u64,
    sender: mpsc::UnboundedSender<ForwardedExecEvent>,
}

#[derive(Debug, Default)]
struct Inner {
    next_id: u64,
    subscribers: HashMap<ExecSubscriptionKey, Vec<Subscriber>>,
}

/// Shared in-memory registry for waiting exec/call IPC subscribers.
#[derive(Debug, Clone, Default)]
pub struct ExecSubscriberRegistry {
    inner: Arc<Mutex<Inner>>,
}

impl ExecSubscriberRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to events for `key`.
    ///
    /// The returned [`ExecSubscription`] is a lease: dropping it unregisters the
    /// subscriber. Receivers are unbounded because producers are the daemon sync
    /// loop and consumers are local IPC writers; disconnected or lagging
    /// receivers are pruned on the next publish/drop.
    pub fn subscribe(&self, key: ExecSubscriptionKey) -> ExecSubscription {
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = inner.next_id;
        inner.next_id = inner.next_id.saturating_add(1);
        inner
            .subscribers
            .entry(key.clone())
            .or_default()
            .push(Subscriber { id, sender });
        ExecSubscription {
            key,
            id,
            receiver,
            registry: Arc::downgrade(&self.inner),
        }
    }

    /// Publish `event` to all subscribers with the event's key.
    ///
    /// Disconnected subscribers are removed. Payload contents are not logged;
    /// callers may log only the returned counts and key/category metadata.
    pub fn publish(&self, event: ForwardedExecEvent) -> ForwardStats {
        let key = event.key();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(list) = inner.subscribers.get_mut(&key) else {
            return ForwardStats::default();
        };

        let mut stats = ForwardStats::default();
        list.retain(|sub| match sub.sender.send(event.clone()) {
            Ok(()) => {
                stats.delivered += 1;
                true
            }
            Err(_) => {
                stats.pruned += 1;
                false
            }
        });
        if list.is_empty() {
            inner.subscribers.remove(&key);
        }
        stats
    }

    /// Return the number of subscribers currently registered for `key`.
    pub fn subscriber_count(&self, key: &ExecSubscriptionKey) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .subscribers
            .get(key)
            .map(Vec::len)
            .unwrap_or(0)
    }

    /// Return the total number of subscribers across all keys.
    pub fn total_subscribers(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .subscribers
            .values()
            .map(Vec::len)
            .sum()
    }
}

/// Lease and receiver for one exec/call subscription.
#[derive(Debug)]
pub struct ExecSubscription {
    key: ExecSubscriptionKey,
    id: u64,
    receiver: mpsc::UnboundedReceiver<ForwardedExecEvent>,
    registry: Weak<Mutex<Inner>>,
}

impl ExecSubscription {
    /// Receive the next forwarded event, or `None` if the registry closed.
    pub async fn recv(&mut self) -> Option<ForwardedExecEvent> {
        self.receiver.recv().await
    }

    /// Try to receive one forwarded event without blocking.
    pub fn try_recv(&mut self) -> Result<ForwardedExecEvent, mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }
}

impl Drop for ExecSubscription {
    fn drop(&mut self) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let mut inner = registry.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(list) = inner.subscribers.get_mut(&self.key) {
            list.retain(|sub| sub.id != self.id);
            if list.is_empty() {
                inner.subscribers.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mx_agent_protocol::schema::{Extra, StreamKind};

    fn chunk(invocation_id: &str, seq: u64, stream: StreamKind) -> ForwardedExecEvent {
        ForwardedExecEvent::StreamChunk(StreamChunk {
            invocation_id: invocation_id.to_string(),
            stream,
            seq,
            encoding: "utf-8".to_string(),
            data: "hello".to_string(),
            eof: false,
            compressed: false,
            sha256: None,
            timestamp: "2026-06-06T00:00:00Z".to_string(),
            extra: Extra::default(),
        })
    }

    #[test]
    fn subscribe_publish_and_drop_cleans_up() {
        let registry = ExecSubscriberRegistry::new();
        let key = ExecSubscriptionKey::Invocation("inv_1".to_string());
        let mut sub = registry.subscribe(key.clone());
        assert_eq!(registry.subscriber_count(&key), 1);

        let stats = registry.publish(chunk("inv_1", 0, StreamKind::Stdout));
        assert_eq!(stats.delivered, 1);
        assert_eq!(stats.pruned, 0);
        assert!(matches!(
            sub.try_recv(),
            Ok(ForwardedExecEvent::StreamChunk(_))
        ));

        drop(sub);
        assert_eq!(registry.subscriber_count(&key), 0);
        assert_eq!(registry.total_subscribers(), 0);
    }

    #[test]
    fn publish_only_delivers_to_matching_invocation() {
        let registry = ExecSubscriberRegistry::new();
        let mut wanted = registry.subscribe(ExecSubscriptionKey::Invocation("inv_1".to_string()));
        let mut other = registry.subscribe(ExecSubscriptionKey::Invocation("inv_2".to_string()));

        let stats = registry.publish(chunk("inv_1", 0, StreamKind::Stderr));
        assert_eq!(stats.delivered, 1);
        assert!(wanted.try_recv().is_ok());
        assert!(matches!(
            other.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn disconnected_subscribers_are_pruned_on_publish() {
        let registry = ExecSubscriberRegistry::new();
        let key = ExecSubscriptionKey::Invocation("inv_1".to_string());
        let mut sub = registry.subscribe(key.clone());
        sub.receiver.close();

        let stats = registry.publish(chunk("inv_1", 0, StreamKind::Stdout));
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.pruned, 1);
        assert_eq!(registry.subscriber_count(&key), 0);
    }

    #[test]
    fn call_response_is_keyed_by_request_id() {
        let event = ForwardedExecEvent::CallResponse(CallResponse {
            request_id: "req_1".to_string(),
            ok: true,
            result: None,
            error: None,
            extra: Extra::default(),
        });
        assert_eq!(
            event.key(),
            ExecSubscriptionKey::Request("req_1".to_string())
        );
    }

    #[test]
    fn terminal_exec_events_are_keyed_by_invocation_id() {
        let finished = ForwardedExecEvent::ExecFinished(ExecFinished {
            invocation_id: "inv_1".to_string(),
            exit_code: Some(0),
            signal: None,
            duration_ms: 1,
            stdout_bytes: 0,
            stderr_bytes: 0,
            truncated: false,
            artifact_mxc: None,
            extra: Extra::default(),
        });
        assert_eq!(
            finished.key(),
            ExecSubscriptionKey::Invocation("inv_1".to_string())
        );
    }
}
