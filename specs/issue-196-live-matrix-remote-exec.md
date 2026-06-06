# Issue #196 — Live Matrix-backed Remote Exec

## Problem Statement

The CLI sends non-PTY `exec` to the daemon over IPC, but targeted `--room`/`--agent` exec still falls back to local loopback. The daemon already has signed exec request helpers, policy/trust authorization, stream chunking, and the subscriber registry from #197. This issue wires those pieces into an end-to-end Matrix-backed remote exec path.

## Goals

- `mx-agent exec --room <room> --agent <agent> -- <cmd>` sends a signed `exec.request` over Matrix instead of running locally.
- Target daemon receives `exec.request` from `/sync`, verifies signature/trust/replay/expiry/policy/target, handles approval-required requests without spawning, emits accepted/rejected, runs the command, emits stream chunks/artifacts and finished, and publishes invocation state.
- Requester daemon waits on the subscriber registry, forwards events to the IPC response, and CLI renders the existing `ExecFrame` stream and exits with the remote process exit code.
- Denied exec never spawns.

## Non-Goals

- Matrix stdin streaming and Matrix cancellation are #198.
- PTY exec remains on the existing local CLI path.
- True live incremental child streaming can be refined later; this implementation may run the process to completion and then emit ordered stream events, as long as Matrix events are consumed by the waiting CLI.

## Relevant Repository Context

- `exec.rs` already provides signed request builders and authorization helpers.
- `exec_ipc.rs` defines daemon IPC `exec.start`, `ExecFrame`, and loopback behavior.
- `exec_subscribers.rs` forwards routed Matrix result events to local subscribers.
- `sync.rs` routes Matrix events and calls live handlers.
- `call.rs` implemented public-key resolution from agent state for #194; exec should reuse the same trust/key model.
- `runner.rs`, `stream.rs`, and `artifact.rs` can run commands and build stream/artifact events.

## Proposed Implementation

### Requester side

- Add `start_exec_matrix(params)` in `exec_ipc` or `exec`.
- Use live Matrix mode only when both `room` and `agent` are present; otherwise keep loopback.
- Restore daemon session, resolve the room, find local requester agent state, load signing key, build and send signed `exec.request` with fresh invocation/request/nonce/timestamps.
- Subscribe to `ExecSubscriptionKey::Invocation(invocation_id)` before sending.
- Wait for forwarded `ExecRejected`, `ExecCancelled`, or `ExecFinished`; collect `StreamChunk`/`StreamArtifact` as `ExecFrame`s; return `ExecStartResult`.

### Target side

- Add `handle_live_exec_request(client, paths, meta, request)`.
- Confirm `target_agent` is a local registered agent in the room.
- Resolve requester agent state and verifying key; ensure published key id matches request signature key id.
- Load trust and policy; authorize with `authorize_exec_request_with_allowance`.
- If rejected, emit `exec.rejected` and audit denial.
- If approval is required, enqueue/emit approval request and do not spawn.
- If allowed, emit `exec.accepted`, publish invocation accepted/running/final state, run the command with policy controls, emit stream chunks/artifacts, emit `exec.finished`.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/exec.rs`
- `crates/mx-agent-daemon/src/exec_ipc.rs`
- `crates/mx-agent-daemon/src/sync.rs`
- `crates/mx-agent-daemon/src/lifecycle.rs`
- `crates/mx-agent-daemon/tests/matrix_integration.rs`
- docs/README/user guide/architecture as needed

## CLI / API Changes

No new CLI flags. Existing `--room`/`--agent` on `mx-agent exec` become live for non-PTY exec when both are provided.

## Data Model / Protocol Changes

No protocol schema changes expected. Existing `exec.request`, `exec.accepted`, `stream.chunk`, `stream.artifact`, `exec.finished`, `exec.rejected`, and invocation state are used.

## Security Considerations

- CLI stays stateless and never sees Matrix credentials or signing keys.
- Room membership alone grants nothing; request must be signed, trusted, unexpired/unreplayed, policy-allowed, and targeted to this daemon.
- Denied/approval-required requests must not spawn.
- Do not log raw command/stdin/output payloads.
- Audit allow/deny decisions with redacted command args.

## Testing Plan

- Unit tests for requester-side mapping of forwarded events into `ExecOutcome`.
- Unit tests/negative tests for target authorization helper paths where practical.
- Matrix E2E with two users: remote `sh -c 'echo hello; echo err >&2; exit 7'` renders stdout/stderr and exits 7.
- Matrix E2E denial sentinel: denied command that would create a file; file remains absent and requester receives rejection.

## Documentation Updates

- README/user guide status: non-PTY `exec` supports Matrix-backed remote dispatch with `--room`/`--agent`; stdin/cancel remain follow-up (#198).

## Risks and Open Questions

- This first live path may emit stream chunks after process completion rather than as the process runs; it still exercises Matrix event transport and CLI consumption. True incremental streaming can be optimized later.
- Approval decision execution after approval remains follow-up unless existing queue processing is already live.

## Implementation Checklist

- [ ] Requester live exec start + wait using subscribers.
- [ ] Target live exec handler.
- [ ] Wire `sync.rs` `ExecRequest` to target handler.
- [ ] Wire lifecycle `exec.start` to live mode when room+agent present.
- [ ] Tests and Matrix E2E.
- [ ] Docs.
- [ ] Required checks.
