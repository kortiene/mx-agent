# Issue #197 — Matrix Stream/Result Forwarding to IPC Subscribers

## Problem Statement

The daemon's `/sync` event router observes Matrix execution result events (`stream.*`, `exec.*`, `call.response`), but there is not yet a daemon-owned in-memory subscription layer that can bridge those events to a CLI waiting over IPC. Live remote exec (#196) needs this foundation so a requester daemon can forward remote stdout/stderr/artifacts/terminal events to the CLI without giving the CLI Matrix credentials or sync state.

## Goals

- Add an in-memory daemon subscriber registry keyed by invocation id and, for call responses, request id.
- Forward routed Matrix result/stream events to matching subscribers.
- Remove disconnected subscribers when publishing fails or when a subscription lease is dropped.
- Preserve stdout/stderr separation, artifact notifications, and terminal exec result events.
- Keep strict stream integrity validation available at the CLI renderer layer; forwarding itself must not reorder or mutate stream payloads.
- Avoid logging payload data.

## Non-Goals

- Do not implement live remote exec (#196) in this issue.
- Do not implement Matrix stdin/cancel (#198) in this issue.
- Do not convert `exec.start` into a long-lived streaming IPC method yet; #196 will use the registry when it sends remote requests.
- Do not make default tests depend on Docker/Matrix.

## Relevant Repository Context

- `crates/mx-agent-daemon/src/event_router.rs` classifies and parses Matrix timeline events into `RoutedEvent` values.
- `crates/mx-agent-daemon/src/sync.rs` routes each `/sync` response and currently has a live handler only for `call.request`.
- `crates/mx-agent-daemon/src/exec_ipc.rs` defines `ExecFrame` and `ExecNotification` wire types.
- `crates/mx-agent-cli/src/stream.rs` already validates ordering/digests and maps strict stream failure to exit 132.
- The CLI must remain stateless and must not receive Matrix tokens, signing keys, or policy state.

## Proposed Implementation

1. Add `crates/mx-agent-daemon/src/exec_subscribers.rs`.
2. Define:
   - `ExecSubscriptionKey` (`Invocation(String)` / `Request(String)`).
   - `ForwardedExecEvent` for stream chunks, artifacts, exec rejected/finished/cancelled, and call responses.
   - `ExecSubscriberRegistry` backed by `Arc<Mutex<HashMap<ExecSubscriptionKey, Vec<Subscriber>>>>`.
   - `ExecSubscription` lease with a receiving channel; dropping it unregisters the subscriber.
3. `publish(event)` sends to subscribers for the event key, prunes disconnected subscribers, and reports delivered/pruned counts.
4. Wire `sync::handle_routed_events` to publish routed events to the registry for:
   - `StreamChunk`
   - `StreamArtifact`
   - `ExecFinished`
   - `ExecRejected`
   - `ExecCancelled`
   - `CallResponse`
5. Add a default shared registry to the daemon lifecycle and pass it into the sync loop.
6. Keep existing `run_matrix_sync(...)` API by wrapping a new `run_matrix_sync_with_subscribers(...)` that takes an optional registry. This keeps existing tests/integration code compatible.
7. Add focused unit tests for lifecycle, pruning, multiple subscribers, and key extraction.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/exec_subscribers.rs` (new)
- `crates/mx-agent-daemon/src/lib.rs`
- `crates/mx-agent-daemon/src/sync.rs`
- `crates/mx-agent-daemon/src/lifecycle.rs`
- `docs/architecture.md`
- `docs/user-guide.md` if user-facing stream behavior wording needs adjustment

## CLI / API Changes

Public daemon API additions:

- `ExecSubscriberRegistry`
- `ExecSubscription`
- `ExecSubscriptionKey`
- `ForwardedExecEvent`
- `ForwardStats`

No CLI command behavior changes in #197.

## Data Model / Protocol Changes

None. This forwards existing Matrix event schemas and existing IPC notification/frame payloads.

## Security Considerations

- Matrix payload content is not logged.
- The registry only forwards events matching an invocation/request key; it does not broadcast unrelated events to every subscriber.
- The CLI remains stateless: it receives structured result/stream events over IPC but does not access Matrix sessions, tokens, signing keys, trust, or policy state.
- Forwarding does not grant execution permission; privileged execution checks remain in #196 target-side authorization.
- Strict stream integrity remains enforced by the renderer/consumer before strict success.

## Testing Plan

- Unit tests for subscribe/drop cleanup.
- Unit tests for disconnected subscriber pruning.
- Unit tests for forwarding stdout/stderr chunks, artifacts, exec finished/rejected/cancelled, and call responses only to matching keys.
- Sync handler unit-adjacent coverage through pure registry/event tests; Matrix E2E waits for #196.

## Documentation Updates

- Architecture doc note that `/sync` result events now feed an in-memory subscriber registry for future live exec/call waiting clients.

## Risks and Open Questions

- #197's full CLI visible acceptance criteria depend on #196 remote exec producing Matrix stream/result events. This issue provides the foundation; #196 will add the remote exec E2E.
- The registry is in-memory and intentionally non-persistent; disconnected/restarted CLIs miss events, consistent with a live stream.

## Implementation Checklist

- [ ] Add registry module/types with public docs.
- [ ] Add tests for registry lifecycle and forwarding.
- [ ] Export APIs from daemon lib.
- [ ] Wire sync routed events into registry publishing.
- [ ] Pass shared registry from daemon lifecycle into sync loop.
- [ ] Update docs.
- [ ] Run fmt/clippy/test/build.
