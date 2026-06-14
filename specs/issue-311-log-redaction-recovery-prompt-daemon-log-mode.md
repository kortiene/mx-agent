# Close the documented-vs-actual secret-handling gaps: telemetry log redaction, recovery-key prompt echo, `daemon.log` mode, env scrub, and `RecoverParams` typing

Issue: #311 (`type:security`, `area:cli`, `area:security`, `priority:p2`). Follow-up to epic #274; found by the 2026-06-11 feature-completeness re-assessment.

## Problem Statement

`docs/security-hardening.md` and `README.md` promise that "the telemetry layer independently redacts any structured field whose key looks sensitive" and substitutes `***redacted***`. No such layer exists. `mx_agent_telemetry::init` installs a plain `tracing_subscriber::fmt` subscriber with **no** field redaction, and `mx_agent_telemetry::redact()` has **zero** production call sites — it is exercised only by its own unit test. The documented backstop that `RecoverParams` and other doc-comments lean on ("never logged; the telemetry layer catches it anyway") is fictional.

Around that missing backstop sit five related secret-handling gaps, all in scope for this issue:

1. **No telemetry field redaction.** The subscriber is a bare `fmt` layer to stderr (`crates/mx-agent-telemetry/src/lib.rs:75-86`), installed once at `crates/mx-agent-cli/src/cli.rs:1019` (which also covers the daemon — `daemon start --foreground` is the same binary with stderr redirected into `daemon.log`). Any future `tracing::debug!(token = …)` leaks in the clear.
2. **Recovery-key prompt echoes.** `resolve_recovery_key` (`crates/mx-agent-cli/src/cli.rs:1461-1489`) prompts and reads with a plain `read_line` and never activates `EchoOffGuard`, so the typed recovery key lands on screen, in scrollback, and in `script(1)` transcripts — the exact leak class #273 / PR #279 fixed for the login password.
3. **`--recovery-key` on argv is silent.** `mx-agent recovery recover --recovery-key <KEY>` (`crates/mx-agent-cli/src/cli.rs:254-260`) is accepted with no warning; the key is then visible in shell history and `ps`. The help text mentions the env var / prompt but carries no exposure warning.
4. **`daemon.log` mode is umask-dependent.** It is opened create+append with no `.mode(0o600)` (`crates/mx-agent-daemon/src/lifecycle.rs:1273-1276`), unlike `session.json`, the status file (`lifecycle.rs:161-174`), and the audit log (`audit.rs:446-462`). Its confidentiality currently rests solely on the `0700` runtime dir.
5. **`is_secret_var` misses mx-agent's own secrets.** `is_secret_var` (`crates/mx-agent-daemon/src/runner.rs:100-102`) checks a fixed list plus `AWS_`/`GOOGLE_`/`AZURE_` prefixes and does not cover `MX_AGENT_PASSWORD` / `MX_AGENT_RECOVERY_KEY`. `sanitize_env` applies the predicate even to allowlisted names as defence-in-depth (`runner.rs:122-139`), but because these names do not match the predicate, an operator who allowlists them leaks them to every spawned child.
6. **`RecoverParams.recovery_key` is a plain `String`.** Under `#[derive(Debug)]` (`crates/mx-agent-daemon/src/recovery_ipc.rs:22-27`) its safety is doc-comment convention, not type discipline; one future `tracing::debug!(?params)` leaks the key, and (per gap 1) no subscriber backstop catches it. `StoredSession` already wraps its tokens in `session::Secret`.

The fix must close the gap between documented and actual behaviour **in whichever direction is chosen**; this spec recommends the *wire-it-in* direction (preferred by the issue, because the docs and `RecoverParams` already assume the backstop exists).

## Goals

- The documented telemetry redaction and the installed subscriber agree. **Recommended:** wire a field-redaction layer into `mx_agent_telemetry::init` that rewrites the value of any field whose key satisfies `is_sensitive_key` to `***redacted***`, in **both** the human and JSON output formats, proven by a unit test that emits a `token`-named field through the subscriber and asserts `***redacted***` (and absence of the secret) in captured output.
- The recovery-key prompt does not echo on a real TTY, while non-TTY stdin (pipes, here-docs, the test harness) still reads normally — mirroring `read_password` exactly, ideally by sharing one no-echo secret reader.
- `mx-agent recovery recover --recovery-key …` prints a one-line stderr warning about shell-history / `ps` exposure, and `--help` documents the exposure and the safer alternatives (`MX_AGENT_RECOVERY_KEY` or the prompt).
- `daemon.log` is created `0600` regardless of umask and re-asserts that mode if a pre-existing file is loose, matching the audit-log pattern.
- `sanitize_env` drops `MX_AGENT_PASSWORD` / `MX_AGENT_RECOVERY_KEY` even when they appear in `env_allowlist`.
- `RecoverParams.recovery_key` is a redacting `Secret`, so `format!("{:?}", params)` shows `***redacted***`, never the key, while the value still round-trips through serde for IPC.
- A new `#[ignore]`d live end-to-end test captures `daemon.log` + CLI stderr after a real `auth login` + `recovery.recover` against the Tuwunel harness and asserts the actual access token and recovery key never appear.
- `cargo fmt --check`, `clippy -D warnings`, build, and the full test suite (including the live Tuwunel suite) stay green.

## Non-Goals

- No change to how secrets are *stored at rest* (`session.json`, crypto-store key, signing key) — those are already `0600` and correct.
- No new redaction taxonomy beyond `mx_agent_telemetry::is_sensitive_key`; reuse the existing needle list (`token`, `secret`, `password`, `passwd`, `api_key`, `apikey`, `access_key`, `private_key`, `credential`, `authorization`). Tuning that list is a separate concern.
- No change to the audit-log argv redactor (`redact_command`, `audit.rs:532`) — it is real and correct; only the *operational-log* claim is false.
- No Windows support, no `unsafe`, no MSRV bump (stays 1.74).
- Not changing the CLI ⇄ daemon trust boundary, signing, policy, or the `auth`/`trust` same-UID carve-out.
- Not persisting the recovery key CLI-side; it stays a pass-through read→forward value.

## Relevant Repository Context

**Workspace / crates touched**
- `crates/mx-agent-telemetry` — owns subscriber setup and the `Secret` / `is_sensitive_key` / `redact` helpers. Depends only on `tracing` + `tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }` (root `Cargo.toml:25-26`).
- `crates/mx-agent-cli` — the `mx-agent` binary; owns argument parsing, the password/recovery prompts, and the single `mx_agent_telemetry::init` call site (`cli.rs:1019`).
- `crates/mx-agent-daemon` — owns `lifecycle.rs` (daemon process + `daemon.log`), `runner.rs` (`is_secret_var` / `sanitize_env`), `recovery_ipc.rs` (`RecoverParams`), `session.rs` (`Secret`, the model to copy), and `audit.rs` (the strongest `0600` pattern; already `use mx_agent_telemetry::{is_sensitive_key, REDACTED};` at `audit.rs:23`).

**Current state (verified at HEAD — do not re-discover)**
- `mx_agent_telemetry::Secret<T>` redacts in `Debug`/`Display` (`lib.rs:118-159`); `is_sensitive_key`/`redact` exist + are unit-tested (`lib.rs:88-116`, tests `lib.rs:174-196`); `redact()` has no production caller.
- `init` (`lib.rs:69-86`) branches on `LogFormat::{Human,Json}` and calls `builder.try_init()` / `builder.json().try_init()`. The format is chosen by `MX_AGENT_LOG_FORMAT` (`human` default, or `json`).
- `daemon::session::Secret` (`session.rs:32-58`) is a `#[serde(transparent)]` newtype over `String`, `Debug` → `Secret(***redacted***)`, `Display` → `***redacted***`, `expose() -> &str`. `StoredSession.access_token`/`refresh_token` use it (`session.rs:64-77`). This is the exact model to copy for `RecoverParams`.
- `read_password` (`cli.rs:1528-1552`) is the no-echo reference: env-var precedence → `eprint!` prompt → `EchoOffGuard::activate()` (returns `None` for non-TTY → plain read) → `read_line` → emit our own newline only when the guard is active → `trim_end_matches(['\n','\r'])`. `EchoOffGuard` is at `cli.rs:1566-1596` (clears `ECHO|ECHONL`, leaves `ICANON`, RAII-restores on drop; `#[cfg(unix)]`).
- `resolve_recovery_key` (`cli.rs:1461-1489`) is the broken twin: arg precedence → env precedence (`ENV_RECOVERY_KEY = "MX_AGENT_RECOVERY_KEY"`, `cli.rs:1098`) → `eprint!("Recovery key: ")` → plain `read_line` (no guard) → `line.trim()` (note: `.trim()`, not `trim_end_matches`, because Matrix recovery keys may contain internal spaces but no leading/trailing ones).
- `RecoveryRecoverArgs` (`cli.rs:254-260`): `#[arg(long = "recovery-key", value_name = "KEY")] recovery_key: Option<String>` with help text "If omitted, it is read from `MX_AGENT_RECOVERY_KEY` or prompted on stdin." `recovery_recover` (`cli.rs:1491-1511`) resolves the key, builds `RecoverParams`, and calls `daemon_ipc_call`.
- Audit-log `0600` pattern (`audit.rs:446-462`): create parent `0700` if missing; `OpenOptions::new().create(true).append(true).mode(0o600).open()`; then `set_permissions(0o600)` to tighten a pre-existing loose file; documented at `audit.rs:438-445`. Uses `std::os::unix::fs::OpenOptionsExt`.
- Status-file `0600` pattern (`lifecycle.rs:161-174`): write-tmp `File::create` → `set_permissions(0o600)` → write → rename. Daemon `0700` runtime dir (`lifecycle.rs:82`); `Paths.log_file = runtime_dir.join("daemon.log")` (`lifecycle.rs:50,69`); `start_background` opens it at `lifecycle.rs:1273-1276` and dups the handle for both stdout and stderr of the spawned `daemon start --foreground`.
- `is_secret_var` (`runner.rs:100-102`) = `SECRET_VARS.contains(name) || SECRET_PREFIXES.starts_with`. `SECRET_VARS` (`runner.rs:67-75`) = `MATRIX_ACCESS_TOKEN`, `MX_AGENT_TOKEN`, `SSH_AUTH_SOCK`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `NPM_TOKEN`. `SECRET_PREFIXES` (`runner.rs:79`) = `AWS_`, `GOOGLE_`, `AZURE_`. `sanitize_env` (`runner.rs:122-139`) filters `is_allowed_var(name, &extra) && !is_secret_var(name)` then applies overrides. Existing tests `runner.rs:585-666`.
- `RecoverParams` (`recovery_ipc.rs:22-27`): `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] pub struct RecoverParams { pub recovery_key: String }`; round-trip test `recovery_ipc.rs:75-83`. `recover_for_session` reads `params.recovery_key` and forwards it to `verification::recover` (`recovery_ipc.rs:66`).
- False/at-risk doc claims to reconcile: `docs/security-hardening.md:165-169` ("The telemetry layer independently redacts any structured field whose key looks sensitive…"), `docs/security-hardening.md:588-591` ("The same secret-key redaction applies to structured fields here."), `README.md:199-201` ("`mx_agent_telemetry::redact` blanks values for secret-looking keys"). Status table `README.md:43` lists "secret redaction … ✅ Implemented".
- Test patterns to follow: `read_password` env/TTY tests (`cli.rs:5984-6107`, with `ENV_PASSWORD_LOCK` and `TERM_SETTINGS_LOCK` mutexes guarding global TTY/env state, and TTY assertions guarded by `isatty(stdin)` so they skip in CI); `sanitize_env` unit tests (`runner.rs:585-666`); audit-log mode tests (`audit.rs:865-930`, including `append_tightens_preexisting_loose_log`); `session::Secret` debug-redaction tests (`session.rs:506-525`). Live recovery tests `live_recovery_enable_and_status` (`matrix_integration.rs:3876+`) and the key-backup round-trip (`matrix_integration.rs:6762+`) call the daemon library in-process; the in-process `Debug`-redaction asserts the issue cites live at `matrix_integration.rs:3976-3982`. Process-level patterns (spawn the real binary with `MX_AGENT_RUNTIME_DIR`, run `daemon start`) live in `crates/mx-agent-cli/tests/daemon_lifecycle.rs` (`BIN = env!("CARGO_BIN_EXE_mx-agent")`).

## Proposed Implementation

### 1. Telemetry field-redaction layer (preferred direction)

Add a redacting field formatter to `crates/mx-agent-telemetry/src/lib.rs` and wire it into both `init` paths. The clean, format-agnostic approach is a **`MakeVisitor` wrapper** that delegates to the format's own field visitor and only swaps sensitive values — so the same wrapper redacts for both the human (`DefaultFields`) and JSON (`JsonFields`) formatters without re-implementing either layout.

```rust
use tracing::field::{Field, Visit};
use tracing_subscriber::field::{MakeVisitor, VisitFmt, VisitOutput};
use tracing_subscriber::fmt::format::{DefaultFields, JsonFields, Writer};

/// Wraps a field visitor so any field whose key is sensitive
/// (`is_sensitive_key`) is recorded as `REDACTED` instead of its real value.
struct Redacting<M>(M);

impl<'a, M> MakeVisitor<Writer<'a>> for Redacting<M>
where
    M: MakeVisitor<Writer<'a>>,
{
    type Visitor = RedactingVisitor<M::Visitor>;
    fn make_visitor(&self, target: Writer<'a>) -> Self::Visitor {
        RedactingVisitor(self.0.make_visitor(target))
    }
}

struct RedactingVisitor<V>(V);

impl<V: Visit> Visit for RedactingVisitor<V> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if is_sensitive_key(field.name()) {
            self.0.record_str(field, REDACTED);
        } else {
            self.0.record_str(field, value);
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if is_sensitive_key(field.name()) {
            self.0.record_str(field, REDACTED);
        } else {
            self.0.record_debug(field, value);
        }
    }
    // record_i64/u64/i128/u128/f64/bool/error/bytes: if sensitive, route to
    // self.0.record_str(field, REDACTED); else forward unchanged.
}

impl<V: VisitOutput<std::fmt::Result>> VisitOutput<std::fmt::Result> for RedactingVisitor<V> {
    fn finish(self) -> std::fmt::Result { self.0.finish() }
}
impl<V: VisitFmt> VisitFmt for RedactingVisitor<V> {
    fn writer(&mut self) -> &mut dyn std::fmt::Write { self.0.writer() }
}
```

Then in `init`:

```rust
let builder = tracing_subscriber::fmt()
    .with_env_filter(filter)
    .with_writer(std::io::stderr)
    .with_target(true);
match LogFormat::from_env() {
    LogFormat::Json => builder.json().fmt_fields(Redacting(JsonFields::new())).try_init(),
    LogFormat::Human => builder.fmt_fields(Redacting(DefaultFields::new())).try_init(),
}
```

Why this shape: the inner visitor (`DefaultVisitor` / `JsonFields`'s visitor) keeps producing the correct per-format layout (`key=value` vs `"key":value`); we only substitute the value when the key is sensitive. Sensitive numeric/bool fields are coerced to the `REDACTED` string, which renders consistently in both formats. The `message` pseudo-field is never sensitive by name, so log messages are untouched.

- Trait-bound caveat: `tracing-subscriber` 0.3's blanket `impl FormatFields for M where M: for<'writer> MakeVisitor<Writer<'writer>>` requires the visitor to be `VisitOutput<fmt::Result>` (and `VisitFmt` for the fmt layer). Implement all four trait pieces (`MakeVisitor`, `Visit`, `VisitOutput`, `VisitFmt`). Confirm the exact import paths against the pinned `tracing-subscriber` version during implementation; the `json` feature is already enabled so `JsonFields` is available.
- Keep the change self-contained in `mx-agent-telemetry`; no public-API change to `init`'s signature.

If, and only if, the JSON `fmt_fields` integration proves too brittle against the crate internals, fall back to the *docs-correction* direction (see Risks). The human path alone, however, is **not** an acceptable end state while the docs claim format-agnostic redaction.

### 2. Shared no-echo secret reader for the recovery prompt

Factor the prompt+read core out of `read_password` into a small `#[cfg(unix)]` helper and reuse it from `resolve_recovery_key`:

```rust
/// Prompt on stderr and read one line from stdin with terminal echo suppressed
/// on a TTY (via `EchoOffGuard`); non-TTY stdin reads normally. Returns the
/// raw line with only the trailing newline stripped (callers apply any further
/// trimming). Never echoes, logs, or stores the value.
fn prompt_secret_line(prompt: &str) -> std::io::Result<String> { … }
```

- Body = current `read_password` lines `1534-1551` generalised over the prompt string: `eprint!("{prompt}")`, flush stderr, `EchoOffGuard::activate()`, `read_line`, emit our own newline when `guard.is_some()`, propagate read error, return `pw.trim_end_matches(['\n','\r']).to_string()`.
- `read_password` keeps its env-var short-circuit, then calls `prompt_secret_line("Matrix password: ")` and returns the result verbatim (preserving today's "no extra trimming" semantics — covered by `read_password_env_var_returned_verbatim`).
- `resolve_recovery_key` keeps its arg-precedence and env-precedence branches, then replaces lines `1473-1481` with `prompt_secret_line("Recovery key: ")`, and **continues to apply `.trim()`** to the returned line (recovery keys can contain internal spaces but not leading/trailing ones; the existing empty-key error path is unchanged). Map a read error to the existing `"mx-agent: could not read recovery key"` + `ExitCode::FAILURE`.
- Result: the recovery prompt no-echoes on a TTY and stays scriptable on a pipe, exactly like the password prompt, with one code path to maintain.

### 3. `--recovery-key` argv-exposure warning + help text

- In `recovery_recover` (or at the top of `resolve_recovery_key`, before returning the arg value), when `args.recovery_key` is `Some(k)` with `!k.is_empty()`, print once to **stderr**:
  `eprintln!("mx-agent: warning: --recovery-key is visible in shell history and `ps`; prefer MX_AGENT_RECOVERY_KEY or the interactive prompt");`
  Stderr keeps stdout/`--json` clean; emit it regardless of `--json`.
- Update the `RecoveryRecoverArgs.recovery_key` doc/help (`cli.rs:256-258`) to state the exposure and steer to the safer inputs, e.g.: "Recovery key recorded when recovery was enabled. WARNING: passing it here exposes it in shell history and `ps`; prefer `MX_AGENT_RECOVERY_KEY` or the interactive prompt. If omitted, it is read from `MX_AGENT_RECOVERY_KEY` or prompted on stdin (no echo)."

### 4. `daemon.log` created `0600`

- In `start_background` (`lifecycle.rs:1273-1276`) replace the bare open with the audit-log pattern: `use std::os::unix::fs::OpenOptionsExt;` then `OpenOptions::new().create(true).append(true).mode(0o600).open(&paths.log_file)?` followed by `log.set_permissions(fs::Permissions::from_mode(0o600))?` to tighten a pre-existing loose file. `try_clone()` for stderr stays.
- Recommended for testability: extract `fn open_log_file(path: &Path) -> io::Result<fs::File>` (atomic `mode(0o600)` + re-assert) so it can be unit-tested directly, mirroring `AuditLog::append`. `start_background` calls it.

### 5. Extend `is_secret_var`

- In `runner.rs`, add `"MX_AGENT_PASSWORD"` and `"MX_AGENT_RECOVERY_KEY"` to `SECRET_VARS`, and OR `mx_agent_telemetry::is_sensitive_key(name)` into `is_secret_var` for defence-in-depth so future `MX_AGENT_*_TOKEN`/`*_SECRET`/`*_PASSWORD` names are caught automatically:
  ```rust
  pub fn is_secret_var(name: &str) -> bool {
      SECRET_VARS.contains(&name)
          || SECRET_PREFIXES.iter().any(|p| name.starts_with(p))
          || mx_agent_telemetry::is_sensitive_key(name)
  }
  ```
  `mx-agent-daemon` already depends on `mx-agent-telemetry` (used in `audit.rs`), so no new dependency. Note `MX_AGENT_PASSWORD` would also be caught by `is_sensitive_key` (contains `password`), but `MX_AGENT_RECOVERY_KEY` matches no needle, so the explicit `SECRET_VARS` entry is required, not optional.
- Update the `is_secret_var` doc-comment (`runner.rs:95-99`) to mention mx-agent's own secrets and the `is_sensitive_key` fallback.

### 6. Wrap `RecoverParams.recovery_key` in `Secret`

- Change `recovery_ipc.rs:22-27` to `pub recovery_key: crate::session::Secret`. `session::Secret` is `#[serde(transparent)]` over `String`, so the IPC wire format is unchanged (still a bare JSON string).
- `recover_for_session` (`recovery_ipc.rs:66`) passes `params.recovery_key.expose()` to `verification::recover`.
- The CLI builds `RecoverParams { recovery_key: mx_agent_daemon::Secret::new(recovery_key) }` — confirm/export `session::Secret` (and a `new`/`From<String>`) from the daemon's public surface (`mx_agent_daemon::Secret`) the same way `RecoverParams`, `RecoveryStatusInfo`, etc. are re-exported; if not already public, add the re-export in `crates/mx-agent-daemon/src/lib.rs`.
- Keep `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]`; `Debug` now redacts via `Secret`. Update the round-trip test (`recovery_ipc.rs:75-83`) to construct with `Secret::new(...)` and compare via `expose()`.

### 7. Live no-secrets-in-logs end-to-end test

Add an `#[ignore]`d test to `crates/mx-agent-daemon/tests/matrix_integration.rs` (same gating string as its siblings: `#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]`). It must exercise the **process** path so it captures the real `daemon.log` and CLI stderr, not just in-process calls:

- Set an isolated `MX_AGENT_RUNTIME_DIR` + `MX_AGENT_DATA_DIR` (temp dirs), spawn the real `mx-agent` binary (`env!("CARGO_BIN_EXE_mx-agent")`), run `auth login` (password via `MX_AGENT_PASSWORD`) and then `daemon start`.
- Enable recovery (capture the one-time key via the daemon library or `recovery enable --json`), then run `recovery recover` feeding the key via `MX_AGENT_RECOVERY_KEY` (not argv), capturing the CLI process's stderr.
- After the flow, read `<runtime_dir>/daemon.log` and the captured CLI stderr and assert they contain **neither** the real access token (`session.access_token.expose()` from the persisted session) **nor** the recovery key string. Also assert (or log) that `daemon.log` mode is `0600`.
- This complements — does not replace — the in-process `Debug`-redaction asserts at `matrix_integration.rs:3976-3982`. If the test-harness shape used by the existing live tests makes a full CLI-process flow impractical, the minimum bar is: drive `recovery.recover` through the real daemon process with a planted token/key and grep the captured `daemon.log` + stderr.

## Affected Files / Crates / Modules

| File | Change |
|---|---|
| `crates/mx-agent-telemetry/src/lib.rs` | Add `Redacting`/`RedactingVisitor` field-redaction wrapper; wire into both `init` formatter paths; add a redaction-through-subscriber unit test. |
| `crates/mx-agent-cli/src/cli.rs` | Extract `prompt_secret_line`; reuse from `read_password` and `resolve_recovery_key`; add `--recovery-key` argv warning; update `RecoveryRecoverArgs` help; build `RecoverParams` with `Secret`; add recovery-prompt no-echo + warning tests. |
| `crates/mx-agent-daemon/src/lifecycle.rs` | `open_log_file` helper with `mode(0o600)` + re-assert; use it in `start_background`; add a log-mode unit test. |
| `crates/mx-agent-daemon/src/runner.rs` | Extend `SECRET_VARS` + OR `is_sensitive_key` into `is_secret_var`; update doc-comment; add `sanitize_env` allowlist-override tests. |
| `crates/mx-agent-daemon/src/recovery_ipc.rs` | `recovery_key: Secret`; `.expose()` at the use site; update round-trip test; add a `Debug`-redaction test. |
| `crates/mx-agent-daemon/src/lib.rs` | Re-export `Secret` (if not already public) for the CLI to construct `RecoverParams`. |
| `crates/mx-agent-daemon/tests/matrix_integration.rs` | New `#[ignore]`d live no-secrets-in-logs test. |
| `docs/security-hardening.md` | Keep claims if redaction is wired (now true); add the recovery-prompt no-echo + `--recovery-key` exposure + `daemon.log 0600` notes. |
| `README.md` | Keep/clarify the redaction line; note the recovery prompt is no-echo; the status-table line stays "✅ Implemented" only if the layer is wired. |

## CLI / API Changes

- **No new commands or flags.** `mx-agent recovery recover` gains a stderr warning when `--recovery-key` is used and updated `--help` text for that flag. Output contract is unchanged: warning goes to **stderr**, human/`--json` results stay on **stdout**.
- `mx_agent_telemetry::init` signature is unchanged (internal subscriber behaviour change only).
- `mx_agent_daemon::Secret` may need to become part of the public re-export surface (additive). `RecoverParams.recovery_key`'s Rust type changes from `String` to `Secret`; this is a source-level change to a daemon-internal/public struct, but the **serialized IPC shape is unchanged** (transparent newtype).

## Data Model / Protocol Changes

- **IPC wire format: none.** `recovery.recover` still sends `{"recovery_key": "<string>"}`; `Secret` is `#[serde(transparent)]`. No protocol version bump, no event-schema change, no policy change.
- Log output: sensitive structured-field *values* now render as `***redacted***`; field *keys* and non-sensitive values are unchanged. JSON logs remain valid JSON.

## Security Considerations

- **No secrets in logs or output** — the entire point. The telemetry layer becomes a real backstop for accidental `tracing` field leaks in both formats; `RecoverParams` gains type-level redaction so a future `?params` cannot leak. The recovery prompt stops echoing; `--recovery-key` carries an exposure warning; `daemon.log` becomes owner-only regardless of umask.
- **CLI never owns Matrix credentials beyond the documented carve-out**: the recovery key stays a pass-through read→forward value, never persisted CLI-side. The coding agent still never sees tokens/keys — `sanitize_env` now also strips `MX_AGENT_PASSWORD`/`MX_AGENT_RECOVERY_KEY` from any spawned child even if allowlisted.
- **Daemon/CLI separation, signing, policy, approval, room-membership-≠-execution** are untouched; this change does not relax any trust boundary.
- **Unix-only, no `unsafe`, MSRV 1.74**: `EchoOffGuard` and `OpenOptionsExt::mode` are already `#[cfg(unix)]` / Unix-only and used elsewhere; the redaction wrapper is portable safe code.
- Redaction is a backstop, not a license to log secrets: keep the "never log raw tokens/keys" discipline and the `Secret` wrappers; the layer only catches mistakes.
- Defence-in-depth ordering: `is_sensitive_key` is substring/case-insensitive, so ORing it into `is_secret_var` can only *widen* what is scrubbed (fail-safe); confirm it does not accidentally drop a needed allowlisted var (e.g. a benign var containing `key` is safe — `key` alone is not a needle).

## Testing Plan

**Unit**
- `mx-agent-telemetry`: build a local subscriber with `Redacting(DefaultFields::new())` (and a second with `JsonFields`) over a `Vec<u8>`-backed `MakeWriter`, run inside `tracing::subscriber::with_default`, emit `tracing::info!(token = "syt_leakme", user = "@a:hs", "msg")`, assert the captured bytes contain `***redacted***` and `@a:hs` but **not** `syt_leakme`; assert the JSON variant parses as valid JSON with `token == "***redacted***"`. (Use a scoped subscriber, not the global `init`, since `try_init` can run once per process.)
- `mx-agent-cli`: recovery-prompt parity tests mirroring `cli.rs:5984-6107` — `MX_AGENT_RECOVERY_KEY` precedence returns without prompting; the TTY-no-echo assertion reuses `EchoOffGuard` (already covered by `echo_off_guard_*` tests, now shared); guard env/TTY mutation with the existing `ENV_*`/`TERM_SETTINGS_LOCK` mutexes. Assert the `--recovery-key` warning text is emitted to stderr (e.g. via a small pure helper that returns the warning string, unit-tested directly, or a process test in `daemon_lifecycle.rs`).
- `mx-agent-daemon` `lifecycle.rs`: `open_log_file` creates `daemon.log` `0600`, and tightens a pre-existing `0644` file back to `0600` (mirror `audit.rs::append_creates_log_and_dir_with_private_modes` and `append_tightens_preexisting_loose_log`).
- `mx-agent-daemon` `runner.rs`: extend the existing `sanitize_env` tests — `MX_AGENT_PASSWORD`/`MX_AGENT_RECOVERY_KEY` are dropped even when present in `env_allowlist`; `is_secret_var` recognises both names.
- `mx-agent-daemon` `recovery_ipc.rs`: `format!("{:?}", RecoverParams { recovery_key: Secret::new("EsTL …") })` contains `***redacted***` and not the key; serde round-trip still preserves the value via `expose()`.

**Integration / live**
- New `#[ignore]`d `matrix_integration.rs` test (section 7): real `auth login` + `recovery.recover` through the daemon process, then grep captured `daemon.log` + CLI stderr for the real access token and recovery key (must be absent). Run via `scripts/matrix_integration_test.sh` in the matrix-integration CI job.
- Optional process test in `crates/mx-agent-cli/tests/daemon_lifecycle.rs`: after `daemon start`, assert `<runtime_dir>/daemon.log` mode is `0600`.

**Gates**: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo build`, `cargo test --all` (default, ignored tests skipped), and the live Tuwunel suite must stay green.

## Documentation Updates

- `docs/security-hardening.md:165-169` and `:588-591`: under the recommended *wire-it-in* direction these claims become **true** — leave them, optionally tightening wording to name the format-agnostic redaction; add a sentence on the recovery prompt being no-echo, the `--recovery-key` argv-exposure warning, and `daemon.log` being `0600`. (If the *docs-correction* fallback is taken instead, rewrite both passages to describe only the `Secret`-type and audit-argv redaction and drop the structured-operational-log claim.)
- `README.md:199-201`: keep the redaction description accurate to the wired behaviour; mention the recovery prompt no-echo near the auth/recovery docs. `README.md:43` status-table line stays "✅ Implemented" only because the layer is now actually wired.
- Update the `RecoveryRecoverArgs` `--help` text (covered in section 3) — this is user-facing documentation surfaced by `--help`.
- Document the new `prompt_secret_line` and `open_log_file` helpers and the `RecoverParams`/`is_secret_var` behaviour changes with doc-comments (public APIs must be documented).

## Risks and Open Questions

- **JSON `fmt_fields` integration is the highest-risk piece.** The `MakeVisitor`/`VisitFmt`/`VisitOutput` trait surface in `tracing-subscriber` 0.3 must be matched exactly, and `JsonFields` must still emit valid JSON through the wrapped visitor. Mitigation: a unit test that asserts the JSON output parses and the sensitive value is redacted. **Fallback if intractable:** take the *docs-correction* direction for the operational-log claim (rewrite `docs/security-hardening.md:165-169`/`:588-591` and `README.md:199-201`), which independently satisfies the acceptance criteria — but the wire-it-in direction is preferred and should be attempted first.
- **Recovery-key trimming semantics.** Matrix recovery keys are space-grouped; `resolve_recovery_key` must keep `.trim()` (leading/trailing only) and must not collapse internal spaces. The shared `prompt_secret_line` returns the line stripped of only the trailing newline, leaving caller-specific trimming to each caller — confirm this preserves both the password (verbatim) and recovery-key (`.trim()`) behaviours and their existing tests.
- **Sensitive numeric/bool fields** are coerced to the `REDACTED` string by the wrapper; verify that is acceptable in JSON (renders as a JSON string, not a number). It is the safe choice and such fields are rare/None today.
- **`mx_agent_daemon::Secret` export.** Confirm whether `session::Secret` is already part of the public re-export surface used by the CLI; if not, add the re-export (additive, low risk).
- **Global subscriber in tests.** `init` installs a process-global subscriber, so the redaction unit test must use a scoped `with_default` subscriber rather than `init`.
- **Live-test feasibility.** Capturing `daemon.log` + CLI stderr through a full CLI-process flow may need harness plumbing the existing in-process live tests don't have; the minimum-bar variant (drive `recovery.recover` through the daemon process with a planted secret) is the fallback if the full flow is impractical.

## Implementation Checklist

1. **Telemetry redaction layer** (`crates/mx-agent-telemetry/src/lib.rs`):
   - [ ] Add `Redacting<M>` + `RedactingVisitor<V>` implementing `MakeVisitor`, `Visit`, `VisitOutput<fmt::Result>`, `VisitFmt`; redact when `is_sensitive_key(field.name())`.
   - [ ] Wire `.fmt_fields(Redacting(DefaultFields::new()))` (human) and `.fmt_fields(Redacting(JsonFields::new()))` (json) into `init`.
   - [ ] Add scoped-subscriber unit tests asserting `token` → `***redacted***` in human and JSON output (and the secret/other fields behave correctly).
2. **Recovery prompt no-echo** (`crates/mx-agent-cli/src/cli.rs`):
   - [ ] Extract `prompt_secret_line(prompt)` from `read_password`'s prompt/read core (`EchoOffGuard`, own-newline-on-TTY, trailing-newline strip).
   - [ ] Refactor `read_password` to call it (preserve verbatim semantics).
   - [ ] Refactor `resolve_recovery_key` to call it and keep `.trim()` + empty-key error.
   - [ ] Add recovery-prompt env-precedence and (TTY-guarded) no-echo tests mirroring the password tests.
3. **`--recovery-key` warning + help** (`cli.rs`):
   - [ ] Emit the one-line stderr exposure warning when `--recovery-key` is supplied.
   - [ ] Update `RecoveryRecoverArgs.recovery_key` help text with the warning and safer alternatives.
4. **`daemon.log` 0600** (`crates/mx-agent-daemon/src/lifecycle.rs`):
   - [ ] Add `open_log_file(path)` with `mode(0o600)` + `set_permissions(0o600)` re-assert.
   - [ ] Use it in `start_background`.
   - [ ] Unit-test create-`0600` and tighten-loose-to-`0600`.
5. **`is_secret_var`** (`crates/mx-agent-daemon/src/runner.rs`):
   - [ ] Add `MX_AGENT_PASSWORD`, `MX_AGENT_RECOVERY_KEY` to `SECRET_VARS`; OR `mx_agent_telemetry::is_sensitive_key` into `is_secret_var`; update doc-comment.
   - [ ] Extend `sanitize_env` tests: both names dropped even when allowlisted.
6. **`RecoverParams` Secret** (`crates/mx-agent-daemon/src/recovery_ipc.rs`, `lib.rs`):
   - [ ] Change `recovery_key` to `Secret`; `.expose()` at the use site; re-export `Secret` if needed; build it `Secret`-wrapped in the CLI.
   - [ ] Update round-trip test; add a `Debug`-redaction test.
7. **Live no-secrets-in-logs test** (`crates/mx-agent-daemon/tests/matrix_integration.rs`):
   - [ ] Add `#[ignore]`d test: real login + recover through the daemon process; grep captured `daemon.log` + stderr for the real token and recovery key (absent); assert `daemon.log` mode `0600`.
8. **Docs** (`docs/security-hardening.md`, `README.md`):
   - [ ] Reconcile the redaction claims with the wired behaviour; add recovery-prompt no-echo, `--recovery-key` exposure, and `daemon.log 0600` notes.
9. **Gates**:
   - [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo build`, `cargo test --all`, and the live Tuwunel suite all green.
