# Issue #195 — Daemon IPC API for exec

## Goal

Keep `mx-agent exec` behind daemon IPC so the CLI remains stateless and does not run non-PTY commands directly. PR #206 added the main `exec.start` loopback path; this issue completes the IPC contract with control methods and notification payloads for future live streaming/remote exec.

## Implemented API

- `exec.start` — runs the current local-loopback daemon executor and returns ordered frames in one response.
- `exec.stdin` — accepts `{ invocation_id, data, eof }` and returns a structured `ExecControlResult`.
- `exec.cancel` — accepts `{ invocation_id, reason? }` and returns a structured `ExecControlResult`.
- `ExecNotification` — serializable daemon-to-CLI notification shape for streaming transports:
  - `exec_accepted`
  - `exec_rejected`
  - `frame` (`chunk`, `artifact`, or `finished`)
  - `exec_cancelled`

## Current behavior

The present loopback executor runs to completion inside `exec.start`. Therefore `exec.stdin` and `exec.cancel` return `accepted: false` with a clear message saying they are available only for live streaming exec invocations. This is intentional: it establishes the IPC method names and wire contracts without pretending there is a live invocation table to control yet.

## Security

- Non-PTY `exec` remains daemon-owned; the CLI forwards requests and renders frames.
- Control payloads are structured and contain no Matrix/session/signing state.
- No command/cwd/stdin payloads are logged by the daemon IPC code.

## Tests

- Unit tests for control-method loopback responses.
- Unit test for notification wire shape.
- Lifecycle dispatch test for `exec.stdin` and `exec.cancel`.
- Existing CLI lifecycle test continues to cover daemon-required `exec.start`, stdout rendering, exit code propagation, and JSON behavior.
