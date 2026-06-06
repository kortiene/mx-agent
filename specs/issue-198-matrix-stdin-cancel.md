# Issue 198: Matrix stdin and cancellation controls

## Goal

Allow live Matrix-backed exec invocations to receive stdin and cancellation controls after `exec.request` has been accepted, without giving the CLI Matrix credentials or relaxing remote execution policy.

## Protocol

- Add timeline event `com.mxagent.exec.stdin.v1`:
  - `invocation_id`
  - base64 `data`
  - `eof`
  - `created_at`
  - `nonce`
  - detached Ed25519 `signature`
- Continue using existing signed `com.mxagent.exec.cancel.v1`.

## Requester behavior

- Remote `exec.start` sets `ExecRequest.stdin = true` when the IPC request carries buffered stdin.
- Buffered stdin is sent as a signed `exec.stdin` frame with `eof = true` after the signed `exec.request` is sent.
- IPC `exec.stdin` and `exec.cancel` send signed Matrix controls when their params include `room`; without a room they retain the local loopback `accepted: false` result.

## Target behavior

- `exec.request` handling spawns a supervised live task and returns to `/sync`, so subsequent control events can be routed while the child is running.
- A running invocation is registered in an in-memory control table keyed by `invocation_id`.
- `exec.stdin` is accepted only when:
  - the event signature verifies against an agent state key in the room,
  - the key is locally trusted,
  - the signing agent is the invocation requester.
- `exec.cancel` uses the same ownership checks, then signals the process group with SIGTERM and escalates to SIGKILL after the runner grace period.
- Cancellation emits `exec.cancelled` and publishes terminal `cancelled` invocation state.

## Non-goals

- PTY interactive streaming remains separate.
- The local loopback `exec.start` path remains synchronous, so local `exec.stdin`/`exec.cancel` still cannot affect it.

## Tests

- Protocol/router unit tests cover the new event type through existing canonical event-count and routing checks.
- Matrix integration should cover buffered stdin round-trip and remote cancellation once the harness can issue concurrent control requests in a stable way.
