//! Daemon Matrix event router for `/sync` (architecture §10.1, §15; issue #192).
//!
//! The daemon's `/sync` loop ([`crate::sync::run_matrix_sync`]) observes every
//! event in a workspace room but, on its own, only tracks batch tokens. This
//! module adds the routing layer that turns raw Matrix sync events into typed
//! mx-agent events and hands them to handlers.
//!
//! # Security model
//!
//! The router is the first gate a remote event passes through, so it is
//! deliberately conservative (architecture §9.2, §13):
//!
//! - **It performs no side effects.** The router classifies, parses,
//!   replay-checks, and dispatches to a handler. It never executes anything
//!   itself. Privileged handlers must still verify the request signature, the
//!   local trust store, local deny-by-default policy, and any approval gate
//!   before running a command — room membership never implies execution rights.
//! - **Undecryptable encrypted events never route.** An `m.room.encrypted`
//!   event that the SDK could not decrypt is skipped before classification, so
//!   an opaque payload can never reach authorization or execution.
//! - **Malformed events never dispatch.** Content that does not deserialize into
//!   its declared type is rejected ([`RouteOutcome::Malformed`]) without a panic
//!   and without calling a handler.
//! - **Privileged requests are replay-checked.** A privileged
//!   `com.mxagent.exec.request.v1` or `com.mxagent.call.request.v1` is admitted
//!   through the persistent [`ReplayCache`] (expiry + nonce replay) before it is
//!   dispatched.
//! - **No payloads are logged.** Callers should log only the event type, room,
//!   sender, event id, and [`RouteOutcome`] — never the event content.
//!
//! The pure routing logic operates on [`IncomingEvent`], a transport-agnostic
//! view, so it is fully unit-testable without a live homeserver.
//! [`events_from_sync_response`] adapts a real [`matrix_sdk`] sync response into
//! [`IncomingEvent`]s.

use serde::de::DeserializeOwned;
use serde_json::Value;

use mx_agent_protocol::events::{state, timeline};
use mx_agent_protocol::schema::{
    ApprovalDecision, ApprovalRequest, CallRequest, CallResponse, ExecAccepted, ExecCancel,
    ExecCancelled, ExecFinished, ExecRejected, ExecRequest, ExecStdin, Heartbeat, InvocationState,
    PtyResize, StreamArtifact, StreamChunk, TaskState,
};

use crate::replay::ReplayCache;

/// Matrix event type used by the homeserver for an encrypted (and, when the SDK
/// could not decrypt it, opaque/undecryptable) event.
const ENCRYPTED_EVENT_TYPE: &str = "m.room.encrypted";

/// A transport-agnostic view of a single Matrix event observed during `/sync`.
///
/// This decouples the routing logic from `matrix_sdk`: the pure router consumes
/// [`IncomingEvent`]s, and [`events_from_sync_response`] builds them from a real
/// sync response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingEvent {
    /// The Matrix event `type`, e.g. `com.mxagent.exec.request.v1`.
    pub event_type: String,
    /// The room the event was observed in.
    pub room_id: String,
    /// The Matrix user ID that sent the event.
    pub sender: String,
    /// The event ID, when known.
    pub event_id: Option<String>,
    /// The state key, for state events.
    pub state_key: Option<String>,
    /// Whether the event is encrypted and could not be decrypted to a plaintext
    /// mx-agent event. Such events are never routed to a handler.
    pub encrypted: bool,
    /// The event `content` payload.
    pub content: Value,
}

/// Non-sensitive metadata about a routed event, passed to handlers and safe to
/// log (it never contains event content).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventMeta {
    /// The Matrix event `type`.
    pub event_type: String,
    /// The room the event was observed in.
    pub room_id: String,
    /// The Matrix user ID that sent the event.
    pub sender: String,
    /// The event ID, when known.
    pub event_id: Option<String>,
    /// The state key, for state events.
    pub state_key: Option<String>,
}

/// The category of a supported mx-agent event, used for dispatch and logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventCategory {
    /// `com.mxagent.exec.request.v1` (privileged).
    ExecRequest,
    /// `com.mxagent.exec.accepted.v1`.
    ExecAccepted,
    /// `com.mxagent.exec.rejected.v1`.
    ExecRejected,
    /// `com.mxagent.exec.finished.v1`.
    ExecFinished,
    /// `com.mxagent.exec.stdin.v1` (privileged).
    ExecStdin,
    /// `com.mxagent.exec.cancel.v1` (privileged).
    ExecCancel,
    /// `com.mxagent.exec.cancelled.v1`.
    ExecCancelled,
    /// `com.mxagent.pty.resize.v1` (interactive PTY window-size hint).
    PtyResize,
    /// `com.mxagent.call.request.v1` (privileged).
    CallRequest,
    /// `com.mxagent.call.response.v1`.
    CallResponse,
    /// `com.mxagent.stream.chunk.v1`.
    StreamChunk,
    /// `com.mxagent.stream.artifact.v1`.
    StreamArtifact,
    /// `com.mxagent.task.v1` state.
    Task,
    /// `com.mxagent.invocation.v1` state.
    Invocation,
    /// `com.mxagent.approval.request.v1`.
    ApprovalRequest,
    /// `com.mxagent.approval.decision.v1`.
    ApprovalDecision,
    /// `com.mxagent.heartbeat.v1`.
    Heartbeat,
}

impl EventCategory {
    /// A stable, non-sensitive label for logs and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecRequest => "exec.request",
            Self::ExecAccepted => "exec.accepted",
            Self::ExecRejected => "exec.rejected",
            Self::ExecFinished => "exec.finished",
            Self::ExecStdin => "exec.stdin",
            Self::ExecCancel => "exec.cancel",
            Self::ExecCancelled => "exec.cancelled",
            Self::PtyResize => "pty.resize",
            Self::CallRequest => "call.request",
            Self::CallResponse => "call.response",
            Self::StreamChunk => "stream.chunk",
            Self::StreamArtifact => "stream.artifact",
            Self::Task => "task",
            Self::Invocation => "invocation",
            Self::ApprovalRequest => "approval.request",
            Self::ApprovalDecision => "approval.decision",
            Self::Heartbeat => "heartbeat",
        }
    }

    /// Whether this category is a privileged request that a handler must
    /// authorize (signature + trust + policy + approval) before acting on.
    ///
    /// Privileged requests are the ones that can cause a remote process to run:
    /// `exec.request`, `exec.cancel`, and `call.request`.
    pub fn is_privileged(self) -> bool {
        matches!(
            self,
            Self::ExecRequest | Self::ExecStdin | Self::ExecCancel | Self::CallRequest
        )
    }
}

/// Map a Matrix event `type` to its [`EventCategory`], or `None` when the type
/// is not an mx-agent event the daemon routes.
pub fn classify(event_type: &str) -> Option<EventCategory> {
    let category = match event_type {
        timeline::EXEC_REQUEST => EventCategory::ExecRequest,
        timeline::EXEC_ACCEPTED => EventCategory::ExecAccepted,
        timeline::EXEC_REJECTED => EventCategory::ExecRejected,
        timeline::EXEC_FINISHED => EventCategory::ExecFinished,
        timeline::EXEC_STDIN => EventCategory::ExecStdin,
        timeline::EXEC_CANCEL => EventCategory::ExecCancel,
        timeline::EXEC_CANCELLED => EventCategory::ExecCancelled,
        timeline::PTY_RESIZE => EventCategory::PtyResize,
        timeline::CALL_REQUEST => EventCategory::CallRequest,
        timeline::CALL_RESPONSE => EventCategory::CallResponse,
        timeline::STREAM_CHUNK => EventCategory::StreamChunk,
        timeline::STREAM_ARTIFACT => EventCategory::StreamArtifact,
        timeline::APPROVAL_REQUEST => EventCategory::ApprovalRequest,
        timeline::APPROVAL_DECISION => EventCategory::ApprovalDecision,
        timeline::HEARTBEAT => EventCategory::Heartbeat,
        state::TASK => EventCategory::Task,
        state::INVOCATION => EventCategory::Invocation,
        _ => return None,
    };
    Some(category)
}

/// A successfully classified and parsed mx-agent event, ready for a handler.
///
/// Larger payloads are boxed so all variants stay a similar, small size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutedEvent {
    /// A privileged request to run a command on this agent.
    ExecRequest(Box<ExecRequest>),
    /// An exec request was accepted by the target.
    ExecAccepted(ExecAccepted),
    /// An exec request was rejected by the target.
    ExecRejected(ExecRejected),
    /// An exec invocation finished.
    ExecFinished(Box<ExecFinished>),
    /// A privileged request to send stdin to a running exec invocation.
    ExecStdin(Box<ExecStdin>),
    /// A privileged request to cancel a running exec invocation.
    ExecCancel(Box<ExecCancel>),
    /// An exec invocation was cancelled.
    ExecCancelled(Box<ExecCancelled>),
    /// A terminal window-resize for a live interactive PTY invocation.
    PtyResize(Box<PtyResize>),
    /// A privileged named-tool call request.
    CallRequest(Box<CallRequest>),
    /// A response to a named-tool call.
    CallResponse(Box<CallResponse>),
    /// A chunk of streamed output.
    StreamChunk(Box<StreamChunk>),
    /// A streamed/uploaded artifact reference.
    StreamArtifact(Box<StreamArtifact>),
    /// A durable task state update.
    Task(Box<TaskState>),
    /// A durable invocation state update.
    Invocation(Box<InvocationState>),
    /// An approval request.
    ApprovalRequest(Box<ApprovalRequest>),
    /// An approval decision.
    ApprovalDecision(Box<ApprovalDecision>),
    /// A liveness heartbeat.
    Heartbeat(Box<Heartbeat>),
}

impl RoutedEvent {
    /// The [`EventCategory`] of this routed event.
    pub fn category(&self) -> EventCategory {
        match self {
            Self::ExecRequest(_) => EventCategory::ExecRequest,
            Self::ExecAccepted(_) => EventCategory::ExecAccepted,
            Self::ExecRejected(_) => EventCategory::ExecRejected,
            Self::ExecFinished(_) => EventCategory::ExecFinished,
            Self::ExecStdin(_) => EventCategory::ExecStdin,
            Self::ExecCancel(_) => EventCategory::ExecCancel,
            Self::ExecCancelled(_) => EventCategory::ExecCancelled,
            Self::PtyResize(_) => EventCategory::PtyResize,
            Self::CallRequest(_) => EventCategory::CallRequest,
            Self::CallResponse(_) => EventCategory::CallResponse,
            Self::StreamChunk(_) => EventCategory::StreamChunk,
            Self::StreamArtifact(_) => EventCategory::StreamArtifact,
            Self::Task(_) => EventCategory::Task,
            Self::Invocation(_) => EventCategory::Invocation,
            Self::ApprovalRequest(_) => EventCategory::ApprovalRequest,
            Self::ApprovalDecision(_) => EventCategory::ApprovalDecision,
            Self::Heartbeat(_) => EventCategory::Heartbeat,
        }
    }
}

/// The outcome of routing a single [`IncomingEvent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    /// The event was dispatched to the handler sink.
    Dispatched(EventCategory),
    /// The event type is not an mx-agent type the daemon routes; ignored.
    Ignored,
    /// The event was encrypted/undecryptable; never parsed or dispatched.
    SkippedEncrypted,
    /// The event content did not match its declared type; rejected, not
    /// dispatched.
    Malformed(EventCategory),
    /// A privileged request failed the replay/expiry check; rejected, not
    /// dispatched.
    ReplayRejected(EventCategory),
}

impl RouteOutcome {
    /// Whether routing reached the handler sink.
    pub fn was_dispatched(&self) -> bool {
        matches!(self, Self::Dispatched(_))
    }
}

/// Routes Matrix sync events to mx-agent handlers, enforcing the router-layer
/// security invariants (see the module documentation).
///
/// The router owns a persistent [`ReplayCache`] so replay protection for
/// privileged requests survives daemon restarts.
#[derive(Debug)]
pub struct EventRouter {
    replay: ReplayCache,
}

impl EventRouter {
    /// Create a router backed by the given replay cache.
    pub fn new(replay: ReplayCache) -> Self {
        Self { replay }
    }

    /// Route a single event, dispatching supported events to `sink`.
    ///
    /// The `sink` is invoked at most once, only for an event that passes every
    /// gate (decrypted, classified, well-formed, and — for privileged requests
    /// — replay-checked). The returned [`RouteOutcome`] describes what happened
    /// and is safe to log.
    pub fn route<S>(&mut self, event: &IncomingEvent, sink: &mut S) -> RouteOutcome
    where
        S: FnMut(&EventMeta, RoutedEvent),
    {
        // 1. Undecryptable encrypted events never reach a handler.
        if event.encrypted || event.event_type == ENCRYPTED_EVENT_TYPE {
            return RouteOutcome::SkippedEncrypted;
        }

        // 2. Unknown event types are ignored.
        let Some(category) = classify(&event.event_type) else {
            return RouteOutcome::Ignored;
        };

        // 3. Parse the content into its typed payload; malformed content is
        //    rejected without dispatch.
        let Some(routed) = parse_routed(category, &event.content) else {
            return RouteOutcome::Malformed(category);
        };

        // 4. Replay/expiry-check privileged execution requests before dispatch.
        //    Both `exec.request` and `call.request` carry a `nonce` and
        //    `expires_at` in their signed content, so the replay cache guards
        //    them here before any handler runs (architecture §9.2, §13). Other
        //    privileged controls (e.g. `exec.cancel`) are scoped to a live
        //    invocation and enforce ownership/signature in their own handlers.
        let replay = match &routed {
            RoutedEvent::ExecRequest(req) => Some((req.nonce.as_str(), req.expires_at.as_str())),
            RoutedEvent::CallRequest(req) => Some((req.nonce.as_str(), req.expires_at.as_str())),
            _ => None,
        };
        if let Some((nonce, expires_at)) = replay {
            if self.replay.admit(nonce, expires_at).is_err() {
                return RouteOutcome::ReplayRejected(category);
            }
        }

        // 5. Dispatch.
        let meta = EventMeta {
            event_type: event.event_type.clone(),
            room_id: event.room_id.clone(),
            sender: event.sender.clone(),
            event_id: event.event_id.clone(),
            state_key: event.state_key.clone(),
        };
        sink(&meta, routed);
        RouteOutcome::Dispatched(category)
    }
}

/// Parse `content` into the [`RoutedEvent`] for `category`, returning `None`
/// when the content does not match the declared type.
fn parse_routed(category: EventCategory, content: &Value) -> Option<RoutedEvent> {
    fn parse<T: DeserializeOwned>(content: &Value) -> Option<T> {
        serde_json::from_value(content.clone()).ok()
    }
    let routed = match category {
        EventCategory::ExecRequest => RoutedEvent::ExecRequest(Box::new(parse(content)?)),
        EventCategory::ExecAccepted => RoutedEvent::ExecAccepted(parse(content)?),
        EventCategory::ExecRejected => RoutedEvent::ExecRejected(parse(content)?),
        EventCategory::ExecFinished => RoutedEvent::ExecFinished(Box::new(parse(content)?)),
        EventCategory::ExecStdin => RoutedEvent::ExecStdin(Box::new(parse(content)?)),
        EventCategory::ExecCancel => RoutedEvent::ExecCancel(Box::new(parse(content)?)),
        EventCategory::ExecCancelled => RoutedEvent::ExecCancelled(Box::new(parse(content)?)),
        EventCategory::PtyResize => RoutedEvent::PtyResize(Box::new(parse(content)?)),
        EventCategory::CallRequest => RoutedEvent::CallRequest(Box::new(parse(content)?)),
        EventCategory::CallResponse => RoutedEvent::CallResponse(Box::new(parse(content)?)),
        EventCategory::StreamChunk => RoutedEvent::StreamChunk(Box::new(parse(content)?)),
        EventCategory::StreamArtifact => RoutedEvent::StreamArtifact(Box::new(parse(content)?)),
        EventCategory::Task => RoutedEvent::Task(Box::new(parse(content)?)),
        EventCategory::Invocation => RoutedEvent::Invocation(Box::new(parse(content)?)),
        EventCategory::ApprovalRequest => RoutedEvent::ApprovalRequest(Box::new(parse(content)?)),
        EventCategory::ApprovalDecision => RoutedEvent::ApprovalDecision(Box::new(parse(content)?)),
        EventCategory::Heartbeat => RoutedEvent::Heartbeat(Box::new(parse(content)?)),
    };
    Some(routed)
}

/// Extract every mx-agent-relevant event from a Matrix `/sync` response.
///
/// Timeline events from joined rooms are converted to [`IncomingEvent`]s (this
/// includes state events that land in the timeline window). Events that fail the
/// router's later gates — unknown types, malformed content, undecryptable
/// encryption — are filtered out by [`EventRouter::route`], not here, so the
/// security decision stays in one place.
///
/// Durable state snapshots that changed strictly before the timeline window are
/// read via the existing `get_state_event(s)` helpers rather than this adapter.
pub fn events_from_sync_response(response: &matrix_sdk::sync::SyncResponse) -> Vec<IncomingEvent> {
    let mut events = Vec::new();
    for (room_id, joined) in &response.rooms.joined {
        let room = room_id.as_str();
        for timeline_event in &joined.timeline.events {
            events.push(incoming_from_timeline(timeline_event, room));
        }
    }
    events
}

/// Build an [`IncomingEvent`] from a single timeline event.
///
/// For an event the SDK could not decrypt, `raw()` returns the original
/// `m.room.encrypted` event, so `encrypted` is set and the router will skip it.
fn incoming_from_timeline(
    event: &matrix_sdk::deserialized_responses::TimelineEvent,
    room_id: &str,
) -> IncomingEvent {
    let raw = event.raw();
    let event_type = raw
        .get_field::<String>("type")
        .ok()
        .flatten()
        .unwrap_or_default();
    let sender = raw
        .get_field::<String>("sender")
        .ok()
        .flatten()
        .unwrap_or_default();
    let event_id = event.event_id().map(|id| id.to_string());
    let state_key = raw.get_field::<String>("state_key").ok().flatten();
    let encrypted = event_type == ENCRYPTED_EVENT_TYPE;
    let content = raw
        .get_field::<Value>("content")
        .ok()
        .flatten()
        .unwrap_or(Value::Null);
    IncomingEvent {
        event_type,
        room_id: room_id.to_string(),
        sender,
        event_id,
        state_key,
        encrypted,
        content,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use crate::session::SessionPaths;

    /// A unique temporary data directory backing a [`SessionPaths`], so the
    /// replay cache can persist without racing other tests or touching the real
    /// data dir.
    struct TempData {
        dir: PathBuf,
    }

    impl TempData {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "mx-agent-router-{}-{}-{}-{}",
                tag,
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                COUNTER.fetch_add(1, Ordering::Relaxed),
            ));
            Self { dir }
        }

        fn paths(&self) -> SessionPaths {
            SessionPaths {
                session_file: self.dir.join("session.json"),
                sync_token_file: self.dir.join("sync_token"),
                data_dir: self.dir.clone(),
            }
        }
    }

    impl Drop for TempData {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn router(tag: &str) -> (EventRouter, TempData) {
        let data = TempData::new(tag);
        let cache = ReplayCache::load(&data.paths()).unwrap();
        (EventRouter::new(cache), data)
    }

    /// A sink that records the categories and metadata it was handed.
    #[derive(Default)]
    struct Recorder {
        dispatched: Vec<EventCategory>,
        metas: Vec<EventMeta>,
    }

    impl Recorder {
        fn sink(&mut self) -> impl FnMut(&EventMeta, RoutedEvent) + '_ {
            move |meta, routed| {
                self.dispatched.push(routed.category());
                self.metas.push(meta.clone());
            }
        }
    }

    fn incoming(event_type: &str, content: Value) -> IncomingEvent {
        IncomingEvent {
            event_type: event_type.to_string(),
            room_id: "!room:server".to_string(),
            sender: "@requester:server".to_string(),
            event_id: Some("$evt".to_string()),
            state_key: None,
            encrypted: false,
            content,
        }
    }

    fn signature() -> Value {
        json!({ "alg": "ed25519", "key_id": "mxagent-ed25519:abc", "sig": "base64" })
    }

    fn exec_request_content(nonce: &str, expires_at: &str) -> Value {
        json!({
            "invocation_id": "inv_1",
            "request_id": "req_1",
            "target_agent": "developer-pi",
            "requesting_agent": "claude-local",
            "command": ["npm", "test"],
            "cwd": "/repo",
            "env": {},
            "stdin": false,
            "stream": true,
            "pty": false,
            "timeout_ms": 600000,
            "task_id": null,
            "created_at": "2026-06-02T12:00:00Z",
            "expires_at": expires_at,
            "nonce": nonce,
            "idempotency_key": "exec:inv_1",
            "signature": signature(),
        })
    }

    fn call_request_content(nonce: &str, expires_at: &str) -> Value {
        json!({
            "invocation_id": "inv_1",
            "request_id": "req_1",
            "tool": "run_tests",
            "args": { "package": "api" },
            "created_at": "2026-06-02T12:00:00Z",
            "expires_at": expires_at,
            "nonce": nonce,
            "requesting_agent": "claude-local",
            "target_agent": "developer-pi",
            "signature": signature(),
        })
    }

    #[test]
    fn classify_maps_every_supported_type() {
        assert_eq!(
            classify(timeline::EXEC_REQUEST),
            Some(EventCategory::ExecRequest)
        );
        assert_eq!(
            classify(timeline::CALL_REQUEST),
            Some(EventCategory::CallRequest)
        );
        assert_eq!(
            classify(timeline::HEARTBEAT),
            Some(EventCategory::Heartbeat)
        );
        assert_eq!(classify(state::TASK), Some(EventCategory::Task));
        assert_eq!(classify(state::INVOCATION), Some(EventCategory::Invocation));
        assert_eq!(
            classify(timeline::PTY_RESIZE),
            Some(EventCategory::PtyResize)
        );
        // Every routed type classifies, and the count matches the issue list.
        let routed_count = timeline::ALL
            .iter()
            .chain(state::ALL.iter())
            .filter(|ty| classify(ty).is_some())
            .count();
        assert_eq!(routed_count, 17);
    }

    #[test]
    fn unknown_event_type_is_ignored() {
        let (mut router, _data) = router("ignore");
        let mut rec = Recorder::default();
        let ev = incoming("m.room.message", json!({ "body": "hello" }));
        let outcome = {
            let mut sink = rec.sink();
            router.route(&ev, &mut sink)
        };
        assert_eq!(outcome, RouteOutcome::Ignored);
        assert!(
            rec.dispatched.is_empty(),
            "unknown events must not dispatch"
        );
    }

    #[test]
    fn known_event_dispatches_with_metadata() {
        let (mut router, _data) = router("dispatch");
        let mut rec = Recorder::default();
        let ev = incoming(
            timeline::HEARTBEAT,
            json!({
                "agent_id": "developer-pi",
                "status": "active",
                "load": { "running_invocations": 0, "max_invocations": 4 },
                "ts": 1780392000000u64,
            }),
        );
        let outcome = {
            let mut sink = rec.sink();
            router.route(&ev, &mut sink)
        };
        assert_eq!(outcome, RouteOutcome::Dispatched(EventCategory::Heartbeat));
        assert_eq!(rec.dispatched, vec![EventCategory::Heartbeat]);
        assert_eq!(rec.metas[0].room_id, "!room:server");
        assert_eq!(rec.metas[0].sender, "@requester:server");
        assert_eq!(rec.metas[0].event_id.as_deref(), Some("$evt"));
    }

    #[test]
    fn task_and_invocation_state_dispatch() {
        let (mut router, _data) = router("state");
        let mut rec = Recorder::default();
        let task = incoming(
            state::TASK,
            json!({
                "task_id": "t1", "title": "x", "description": "", "state": "pending",
                "assigned_to": "", "created_by": "@a:s", "depends_on": [], "blocks": [],
                "invocation_id": null, "created_at": "2026-06-02T12:00:00Z",
                "updated_at": "2026-06-02T12:00:00Z", "state_rev": 1,
                "previous_event_id": null, "result": null,
            }),
        );
        let inv = incoming(
            state::INVOCATION,
            json!({
                "invocation_id": "inv_1", "task_id": null, "requester": "@a:s",
                "target": "developer-pi", "state": "running",
                "created_at": "2026-06-02T12:00:00Z", "updated_at": "2026-06-02T12:00:00Z",
                "exit_code": null, "state_rev": 1,
            }),
        );
        let mut sink = rec.sink();
        assert!(router.route(&task, &mut sink).was_dispatched());
        assert!(router.route(&inv, &mut sink).was_dispatched());
        drop(sink);
        assert_eq!(
            rec.dispatched,
            vec![EventCategory::Task, EventCategory::Invocation]
        );
    }

    /// Acceptance: malformed privileged events must not execute (reach a
    /// handler). A privileged `exec.request`/`call.request` with content that
    /// does not match the schema is rejected and never dispatched.
    #[test]
    fn malformed_privileged_event_is_not_dispatched() {
        let (mut router, _data) = router("malformed");
        let mut rec = Recorder::default();
        // exec.request missing required fields (command, signature, ...).
        let bad_exec = incoming(timeline::EXEC_REQUEST, json!({ "invocation_id": "inv_1" }));
        // call.request missing required fields.
        let bad_call = incoming(timeline::CALL_REQUEST, json!({ "tool": "run_tests" }));
        let mut sink = rec.sink();
        assert_eq!(
            router.route(&bad_exec, &mut sink),
            RouteOutcome::Malformed(EventCategory::ExecRequest)
        );
        assert_eq!(
            router.route(&bad_call, &mut sink),
            RouteOutcome::Malformed(EventCategory::CallRequest)
        );
        drop(sink);
        assert!(
            rec.dispatched.is_empty(),
            "malformed privileged events must never reach a handler"
        );
    }

    /// Acceptance (E2EE): an undecryptable encrypted privileged event must not
    /// route. It is skipped before classification or parsing.
    #[test]
    fn encrypted_privileged_event_is_not_routed() {
        let (mut router, _data) = router("encrypted");
        let mut rec = Recorder::default();
        // Flagged via the `encrypted` bit...
        let mut ev = incoming(
            timeline::EXEC_REQUEST,
            exec_request_content("n1", "2099-01-01T00:00:00Z"),
        );
        ev.encrypted = true;
        // ...and via the raw m.room.encrypted type with opaque content.
        let opaque = incoming(
            ENCRYPTED_EVENT_TYPE,
            json!({ "algorithm": "m.megolm.v1", "ciphertext": "..." }),
        );
        let mut sink = rec.sink();
        assert_eq!(router.route(&ev, &mut sink), RouteOutcome::SkippedEncrypted);
        assert_eq!(
            router.route(&opaque, &mut sink),
            RouteOutcome::SkippedEncrypted
        );
        drop(sink);
        assert!(
            rec.dispatched.is_empty(),
            "encrypted/undecryptable events must never reach a handler"
        );
    }

    #[test]
    fn valid_exec_request_dispatches_once_then_replay_is_rejected() {
        let (mut router, _data) = router("replay");
        let mut rec = Recorder::default();
        let ev = incoming(
            timeline::EXEC_REQUEST,
            exec_request_content("nonce-x", "2099-01-01T00:00:00Z"),
        );
        let mut sink = rec.sink();
        // First time: admitted and dispatched.
        assert_eq!(
            router.route(&ev, &mut sink),
            RouteOutcome::Dispatched(EventCategory::ExecRequest)
        );
        // Replay of the same nonce: rejected, not dispatched again.
        assert_eq!(
            router.route(&ev, &mut sink),
            RouteOutcome::ReplayRejected(EventCategory::ExecRequest)
        );
        drop(sink);
        assert_eq!(rec.dispatched, vec![EventCategory::ExecRequest]);
    }

    #[test]
    fn valid_call_request_dispatches_once_then_replay_is_rejected() {
        // Parallels the exec.request replay test: a signed call.request is
        // admitted once, and a byte-identical re-send (replay) is rejected by the
        // router before it can reach the call handler a second time.
        let (mut router, _data) = router("call-replay");
        let mut rec = Recorder::default();
        let ev = incoming(
            timeline::CALL_REQUEST,
            call_request_content("call-nonce-x", "2099-01-01T00:00:00Z"),
        );
        let mut sink = rec.sink();
        assert_eq!(
            router.route(&ev, &mut sink),
            RouteOutcome::Dispatched(EventCategory::CallRequest)
        );
        assert_eq!(
            router.route(&ev, &mut sink),
            RouteOutcome::ReplayRejected(EventCategory::CallRequest)
        );
        drop(sink);
        assert_eq!(rec.dispatched, vec![EventCategory::CallRequest]);
    }

    #[test]
    fn expired_call_request_is_rejected() {
        let (mut router, _data) = router("call-expired");
        let mut rec = Recorder::default();
        let ev = incoming(
            timeline::CALL_REQUEST,
            call_request_content("call-nonce-e", "1971-01-01T00:00:00Z"),
        );
        let mut sink = rec.sink();
        assert_eq!(
            router.route(&ev, &mut sink),
            RouteOutcome::ReplayRejected(EventCategory::CallRequest)
        );
        drop(sink);
        assert!(rec.dispatched.is_empty());
    }

    #[test]
    fn expired_exec_request_is_rejected() {
        let (mut router, _data) = router("expired");
        let mut rec = Recorder::default();
        // Expiry in the distant past relative to wall-clock now.
        let ev = incoming(
            timeline::EXEC_REQUEST,
            exec_request_content("nonce-e", "1971-01-01T00:00:00Z"),
        );
        let mut sink = rec.sink();
        assert_eq!(
            router.route(&ev, &mut sink),
            RouteOutcome::ReplayRejected(EventCategory::ExecRequest)
        );
        drop(sink);
        assert!(rec.dispatched.is_empty());
    }

    #[test]
    fn privileged_classification_is_correct() {
        assert!(EventCategory::ExecRequest.is_privileged());
        assert!(EventCategory::ExecCancel.is_privileged());
        assert!(EventCategory::CallRequest.is_privileged());
        assert!(!EventCategory::Heartbeat.is_privileged());
        assert!(!EventCategory::Task.is_privileged());
        assert!(!EventCategory::ExecFinished.is_privileged());
    }
}
