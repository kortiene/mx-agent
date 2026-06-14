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
//!
//! Each subscription is **pinned to the executing agent's Matrix user id**
//! ([`ExecSubscriberRegistry::subscribe`]'s `expected_sender`). A routed result
//! event is forwarded only when its Matrix sender matches that pin, so a forged
//! `stream.chunk` / `exec.finished` / `call.response` published by any other
//! room member is dropped before it reaches a waiting consumer (architecture
//! §1.2, §13; issue #304). The result plane therefore never trusts mere room
//! presence — the same deny-by-default stance the request plane already takes.

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
    /// Number of subscribers the event was withheld from because its Matrix
    /// sender did not match the subscriber's pinned executing agent (a forged or
    /// foreign result event — see [`ExecSubscriberRegistry::publish`]).
    pub filtered: usize,
}

#[derive(Debug)]
struct Subscriber {
    id: u64,
    /// Matrix user id of the agent this subscription expects results from. The
    /// dispatcher resolves this from the target agent's `matrix_user_id` before
    /// subscribing; only events whose `sender` equals it are delivered.
    expected_sender: String,
    tx: mpsc::UnboundedSender<ForwardedExecEvent>,
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

    /// Subscribe to events for `key`, pinned to `expected_sender`.
    ///
    /// `expected_sender` is the Matrix user id of the agent the dispatcher
    /// targeted (resolved from its `matrix_user_id`). [`publish`](Self::publish)
    /// delivers an event only when its Matrix sender equals this value, so a
    /// result/stream event forged by any other room member is dropped before it
    /// reaches the waiting consumer — room membership is never execution
    /// permission (architecture §1.2, §13).
    ///
    /// The returned [`ExecSubscription`] is a lease: dropping it unregisters the
    /// subscriber. Receivers are unbounded because producers are the daemon sync
    /// loop and consumers are local IPC writers; disconnected or lagging
    /// receivers are pruned on the next publish/drop.
    pub fn subscribe(&self, key: ExecSubscriptionKey, expected_sender: String) -> ExecSubscription {
        let (tx, receiver) = mpsc::unbounded_channel();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = inner.next_id;
        inner.next_id = inner.next_id.saturating_add(1);
        inner
            .subscribers
            .entry(key.clone())
            .or_default()
            .push(Subscriber {
                id,
                expected_sender,
                tx,
            });
        ExecSubscription {
            key,
            id,
            receiver,
            registry: Arc::downgrade(&self.inner),
        }
    }

    /// Publish `event` (sent by Matrix user `sender`) to its subscribers.
    ///
    /// Deny-by-default sender pinning: the event is delivered only to subscribers
    /// whose pinned `expected_sender` equals `sender`. A mismatch is counted as
    /// [`ForwardStats::filtered`] and the subscriber is retained (the legitimate
    /// executor's event may still arrive) — a forged result from a non-executing
    /// member can never satisfy a waiting consumer. Disconnected subscribers are
    /// removed. Payload contents are not logged; callers may log only the
    /// returned counts and key/category metadata.
    pub fn publish(&self, event: ForwardedExecEvent, sender: &str) -> ForwardStats {
        let key = event.key();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(list) = inner.subscribers.get_mut(&key) else {
            return ForwardStats::default();
        };

        let mut stats = ForwardStats::default();
        list.retain(|sub| {
            if sub.expected_sender != sender {
                stats.filtered += 1;
                return true;
            }
            match sub.tx.send(event.clone()) {
                Ok(()) => {
                    stats.delivered += 1;
                    true
                }
                Err(_) => {
                    stats.pruned += 1;
                    false
                }
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

    const EXEC: &str = "@exec:hs";
    const MEMBER: &str = "@member:hs";

    fn cancelled(invocation_id: &str) -> ForwardedExecEvent {
        ForwardedExecEvent::ExecCancelled(ExecCancelled {
            invocation_id: invocation_id.to_string(),
            signal_sent: "SIGTERM".to_string(),
            killed_process_group: false,
            finished_at: "2026-06-06T00:00:00Z".to_string(),
            extra: Extra::default(),
        })
    }

    fn rejected(invocation_id: &str) -> ForwardedExecEvent {
        ForwardedExecEvent::ExecRejected(ExecRejected {
            invocation_id: invocation_id.to_string(),
            reason: "policy_denied".to_string(),
            extra: Extra::default(),
        })
    }

    fn artifact(invocation_id: &str) -> ForwardedExecEvent {
        ForwardedExecEvent::StreamArtifact(StreamArtifact {
            invocation_id: invocation_id.to_string(),
            stream: StreamKind::Stdout,
            name: "stdout.log".to_string(),
            mime_type: "text/plain".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            mxc_uri: "mxc://s/a".to_string(),
            tail_preview: String::new(),
            encrypted_file: None,
            extra: Extra::default(),
        })
    }

    fn call_response(request_id: &str) -> ForwardedExecEvent {
        ForwardedExecEvent::CallResponse(CallResponse {
            request_id: request_id.to_string(),
            ok: true,
            result: None,
            error: None,
            extra: Extra::default(),
        })
    }

    #[test]
    fn subscribe_publish_and_drop_cleans_up() {
        let registry = ExecSubscriberRegistry::new();
        let key = ExecSubscriptionKey::Invocation("inv_1".to_string());
        let mut sub = registry.subscribe(key.clone(), EXEC.to_string());
        assert_eq!(registry.subscriber_count(&key), 1);

        let stats = registry.publish(chunk("inv_1", 0, StreamKind::Stdout), EXEC);
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
        let mut wanted = registry.subscribe(
            ExecSubscriptionKey::Invocation("inv_1".to_string()),
            EXEC.to_string(),
        );
        let mut other = registry.subscribe(
            ExecSubscriptionKey::Invocation("inv_2".to_string()),
            EXEC.to_string(),
        );

        let stats = registry.publish(chunk("inv_1", 0, StreamKind::Stderr), EXEC);
        assert_eq!(stats.delivered, 1);
        assert!(wanted.try_recv().is_ok());
        assert!(matches!(
            other.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn publish_drops_events_from_an_unexpected_sender() {
        // A forged result event whose Matrix sender is not the pinned executing
        // agent must never reach the waiting consumer (issue #304): it is counted
        // as filtered, the subscription survives, and a later legitimate event
        // from the real executor is still delivered.
        let registry = ExecSubscriberRegistry::new();
        let key = ExecSubscriptionKey::Invocation("inv_1".to_string());
        let mut sub = registry.subscribe(key.clone(), EXEC.to_string());

        let forged = registry.publish(chunk("inv_1", 0, StreamKind::Stdout), MEMBER);
        assert_eq!(forged.delivered, 0);
        assert_eq!(forged.filtered, 1);
        assert!(matches!(
            sub.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        // The subscription is retained so the real executor can still resolve it.
        assert_eq!(registry.subscriber_count(&key), 1);

        let legit = registry.publish(chunk("inv_1", 1, StreamKind::Stdout), EXEC);
        assert_eq!(legit.delivered, 1);
        assert!(sub.try_recv().is_ok());
    }

    #[test]
    fn publish_drops_forged_terminal_finished_event() {
        // A faked exec.finished (e.g. a forged exit status) from a non-executing
        // member must not be delivered as the invocation's terminal frame.
        let registry = ExecSubscriberRegistry::new();
        let key = ExecSubscriptionKey::Invocation("inv_1".to_string());
        let mut sub = registry.subscribe(key.clone(), EXEC.to_string());
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
        let stats = registry.publish(finished, MEMBER);
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.filtered, 1);
        assert!(matches!(
            sub.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn disconnected_subscribers_are_pruned_on_publish() {
        let registry = ExecSubscriberRegistry::new();
        let key = ExecSubscriptionKey::Invocation("inv_1".to_string());
        let mut sub = registry.subscribe(key.clone(), EXEC.to_string());
        sub.receiver.close();

        let stats = registry.publish(chunk("inv_1", 0, StreamKind::Stdout), EXEC);
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

    #[test]
    fn publish_drops_forged_exec_cancelled_from_unexpected_sender() {
        // A faked exec.cancelled from a non-executing room member must be dropped
        // before reaching a waiting subscriber (issue #304).
        let registry = ExecSubscriberRegistry::new();
        let key = ExecSubscriptionKey::Invocation("inv_1".to_string());
        let mut sub = registry.subscribe(key.clone(), EXEC.to_string());
        let stats = registry.publish(cancelled("inv_1"), MEMBER);
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.filtered, 1);
        assert!(matches!(
            sub.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        // Subscription retained for the legitimate executor.
        assert_eq!(registry.subscriber_count(&key), 1);
    }

    #[test]
    fn publish_drops_forged_exec_rejected_from_unexpected_sender() {
        // A faked exec.rejected (e.g. a forged policy denial) from a non-executing
        // member must not be delivered — a subscriber must not terminate believing
        // the exec was rejected when it was not (issue #304).
        let registry = ExecSubscriberRegistry::new();
        let key = ExecSubscriptionKey::Invocation("inv_1".to_string());
        let mut sub = registry.subscribe(key.clone(), EXEC.to_string());
        let stats = registry.publish(rejected("inv_1"), MEMBER);
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.filtered, 1);
        assert!(matches!(
            sub.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn publish_drops_forged_stream_artifact_from_unexpected_sender() {
        // A forged stream.artifact from a non-executing member (a shadowed artifact
        // announcement) must be dropped; only the legitimate executor's artifact
        // notification is delivered (issue #304).
        let registry = ExecSubscriberRegistry::new();
        let key = ExecSubscriptionKey::Invocation("inv_1".to_string());
        let mut sub = registry.subscribe(key.clone(), EXEC.to_string());
        let stats = registry.publish(artifact("inv_1"), MEMBER);
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.filtered, 1);
        assert!(matches!(
            sub.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        // Legitimate artifact from the executing agent is still delivered.
        let legit = registry.publish(artifact("inv_1"), EXEC);
        assert_eq!(legit.delivered, 1);
        assert!(matches!(
            sub.try_recv(),
            Ok(ForwardedExecEvent::StreamArtifact(_))
        ));
    }

    #[test]
    fn publish_drops_forged_call_response_from_unexpected_sender() {
        // A forged call.response from a non-executing member must be filtered out
        // before reaching the waiting subscriber: room membership does not confer
        // the right to resolve a call (issue #304).
        let registry = ExecSubscriberRegistry::new();
        let key = ExecSubscriptionKey::Request("req_1".to_string());
        let mut sub = registry.subscribe(key.clone(), EXEC.to_string());
        let forged = registry.publish(call_response("req_1"), MEMBER);
        assert_eq!(forged.delivered, 0);
        assert_eq!(forged.filtered, 1);
        assert!(matches!(
            sub.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        // The subscription is retained so the legitimate executor's response can
        // still arrive later.
        assert_eq!(registry.subscriber_count(&key), 1);
        let legit = registry.publish(call_response("req_1"), EXEC);
        assert_eq!(legit.delivered, 1);
        assert!(matches!(
            sub.try_recv(),
            Ok(ForwardedExecEvent::CallResponse(_))
        ));
    }

    #[test]
    fn publish_selective_delivery_with_different_expected_senders() {
        // Two subscribers on the same key but pinned to different executing agents:
        // an event from EXEC is delivered only to the EXEC-pinned subscriber and
        // filtered for the MEMBER-pinned one. This verifies sender pinning is
        // per-subscriber, not per-key (issue #304).
        let registry = ExecSubscriberRegistry::new();
        let key = ExecSubscriptionKey::Invocation("inv_1".to_string());
        let mut sub_exec = registry.subscribe(key.clone(), EXEC.to_string());
        let mut sub_member = registry.subscribe(key.clone(), MEMBER.to_string());
        assert_eq!(registry.subscriber_count(&key), 2);

        let stats = registry.publish(chunk("inv_1", 0, StreamKind::Stdout), EXEC);
        assert_eq!(stats.delivered, 1);
        assert_eq!(stats.filtered, 1);
        assert!(sub_exec.try_recv().is_ok());
        assert!(matches!(
            sub_member.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}
