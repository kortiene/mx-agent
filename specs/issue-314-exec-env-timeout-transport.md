# Issue #314 — Exec transport: caller-set env/timeout, no premature abandon, surfaced truncation

## Problem

The signed exec wire schema carries `env` and `timeout_ms` and the receiver honors
both, but no caller can set them: the CLI has no `--env`/`--timeout`, the IPC
params lack the fields, and both live senders hardcode `env: Default::default()` /
`timeout_ms: 600_000`. The requester also abandons after a fixed ~120 s wait —
**without** sending a signed `exec.cancel` — while having told the remote it may
run up to 600 s, leaving it running unsupervised. The Matrix task dispatcher drops
`env`/`timeout_ms`. The truthful `truncated` flag (#268) is never shown to the user.

## Goals (acceptance criteria)

- `mx-agent exec --env K=V --timeout <dur> -- cmd` round-trips: the signed request
  carries both; the receiver runs with the env override and `min(policy cap,
  requested)` timeout (unchanged receiver precedence).
- The requester no longer abandons a healthy run at a fixed 120 s; on abandon it
  sends a signed `exec.cancel` and maps the requester-side timeout to exit 129.
- Matrix task dispatch forwards `env`/`timeout_ms`; user-guide "still landing" closed.
- `truncated` is visible to the user on both the non-PTY and PTY paths.
- `--stdin`/`--stream` semantics resolved (removed; docs updated).
- fmt/clippy/build/test green; live Tuwunel suite stays green.

## Design

### CLI flags + params
- `ExecArgs`: add `--env KEY=VALUE` (repeatable) and `--timeout <DURATION>`
  (`120`, `5m`, `500ms`, `2h` via a small `parse_timeout_ms` value parser, bare
  number = seconds). Remove `--stdin` (piped stdin is already auto-detected) and
  `--stream` (the daemon consults `request.stream` zero times; incremental
  emission is the deferred stretch / #241).
- `ExecStartParams` and `ExecPtyParams`: add `#[serde(default)] env:
  BTreeMap<String,String>` and `#[serde(default)] timeout_ms: Option<u64>`.

### Senders
- `start_exec_matrix` and `setup_remote_pty`: forward `params.env` and
  `params.timeout_ms.unwrap_or(DEFAULT_REMOTE_EXEC_TIMEOUT_MS)` instead of the
  hardcoded values. Receiver-side `min(policy cap, requested)` is unchanged.

### Requester wait + cancel-on-abandon (non-PTY)
- Replace the fixed 120 s deadline with `requested_timeout + grace` (30 s), and
  stop abandoning on the 5 s poll window (loop until the real deadline) — this
  also fixes a latent early-abandon on a silent command. On the real deadline,
  send a signed `exec.cancel` via `send_exec_cancel` and return
  `ExecOutcome::Error { kind: Timeout }`.
- New `ExecErrorKind::Timeout` → CLI exit **129** (architecture §5.3). The PTY
  drain loop has no fixed wall and is left as-is.

### Surface truncated
- `StreamOutcome` gains `truncated`; `render_stream_with` sets it from the
  `Finished` frame. `cmd_exec` prints a stderr notice when set.
- PTY render loop captures `Finished { truncated }` and prints the same notice.

### Matrix task dispatch
- Destructure `env`/`timeout_ms` from `TaskAction::Exec` and set them on the
  `ExecStartParams`, matching local dispatch.

### Docs / decisions
- `exec.cancelled` does **not** gain a `truncated` field: a cancelled run's
  output is incomplete by definition, so the cancel path intentionally drops the
  capture summary. Recorded in architecture §5/§7.
- architecture §5.3: exit 129 now emitted for a requester-side timeout (126/131
  remain planned). user-guide "still landing" → shipped. cli-reference: `--env`/
  `--timeout` documented, `--stdin`/`--stream` removed, truncation notice noted.

## Affected code

- `crates/mx-agent-cli/src/cli.rs` — `ExecArgs`, `parse_timeout_ms`, `cmd_exec`,
  `cmd_exec_pty`, PTY `Finished` handling, exit-129 mapping.
- `crates/mx-agent-cli/src/stream.rs` — `StreamOutcome.truncated`.
- `crates/mx-agent-daemon/src/exec_ipc.rs` — `ExecStartParams` fields, sender,
  requester deadline + cancel, `ExecErrorKind::Timeout`.
- `crates/mx-agent-daemon/src/pty_ipc.rs` — `ExecPtyParams` fields, sender.
- `crates/mx-agent-daemon/src/task_dispatch_matrix.rs` — forward env/timeout.
- Docs: architecture.md, user-guide.md, cli-reference.md; `doc_drift.rs` guard.

## Security

- env/timeout travel CLI → daemon IPC → daemon-signed request; signing and the
  Matrix client stay in the daemon. `--env` values never appear in daemon logs.
- Caller env/timeout remain subordinate to the receiver's trust + deny-by-default
  policy; `allowance.max_runtime_ms` still caps the timeout.
- The abandon `exec.cancel` is signed and passes `authorize_exec_cancel` like
  every cancel. Unix-only; no `unsafe`; MSRV 1.74.

## Testing

- Unit: `parse_timeout_ms` (seconds/units/errors); request building forwards
  env/timeout (exec_ipc + pty_ipc); `ExecErrorKind::Timeout` → 129; renderer sets
  `truncated` and the notice prints; task_dispatch_matrix forwards env/timeout.
- Integration: a remote exec whose result never arrives within `timeout+grace`
  triggers a signed `exec.cancel` (subscriber-registry test); live Tuwunel
  scenario for `--env`/`--timeout` round-trip + cancel-on-abandon.
- E2E decision: the live Tuwunel suite covers the remote round-trip; no new Docker
  in default `cargo test --all`.
