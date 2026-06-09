# Minor Hardening: Disable Terminal Echo in `read_password`; Reject Floats in `canonical_json`

## Problem Statement
Two small, independent robustness gaps surfaced during the v0.2.0 feature-completeness
assessment (commit `aefbd6f`). Both are latent hazards rather than active failures, but
each contradicts a stated contract.

1. **Echoed password (`area:cli`).** `read_password` in the CLI prompts for the Matrix
   login password on stderr and reads a line with terminal echo still enabled. The typed
   password appears on screen as it is entered and can persist in terminal scrollback or a
   `script(1)` transcript. The doc comment at `crates/mx-agent-cli/src/cli.rs:1417`
   ("The password is never echoed back, logged, or passed as an argument.") and the
   user-facing claim in `docs/cli-reference.md:337,361` ("not echoed") are therefore
   inaccurate. The `MX_AGENT_PASSWORD` environment-variable path and the correct
   avoidance of argv are unaffected — only the interactive TTY prompt echoes.

2. **Unrejected floats (`area:protocol`).** `canonical_json::write_value` serializes any
   `serde_json::Number` via `Number::to_string` (`canonical_json.rs:42`) and never rejects
   floating-point values. Matrix canonical JSON
   (<https://spec.matrix.org/latest/appendices/#canonical-json>) forbids floats, and this
   encoder is the byte representation that Ed25519 signatures are computed over
   (`signing::signing_bytes` → `to_canonical_bytes`). Today every mx-agent payload uses
   integers and strings, so the gap is not exercised; but any future float-bearing field
   would canonicalize divergently from a strict Matrix implementation, silently breaking
   cross-peer signature agreement. The module currently advertises "the same rules as
   Matrix canonical JSON" without enforcing the no-float rule.

## Goals
- Disable terminal echo for the interactive prompt path in `read_password`, restoring the
  prior terminal state on normal return, on error, and on panic unwind.
- After the fix, characters typed at the `Matrix password:` prompt are not echoed to the
  TTY, making the `cli.rs:1417` doc comment and the `docs/cli-reference.md` claims accurate.
- Keep `MX_AGENT_PASSWORD` precedence and the argv-avoidance behavior exactly as they are.
- Make `canonical_json` enforce the integer/string-only number contract: reject (or refuse
  to encode) non-integer `Number` values, and propagate that rejection through
  `to_canonical_bytes`, `signing_bytes`, `sign`, `sign_into`, and `verify`.
- Add unit tests proving (a) a float-bearing value is rejected by the encoder/signing path,
  and (b) integers still encode unchanged (no regression in the known-answer signing vector).
- Update the module docs to state the enforced contract explicitly.

## Non-Goals
- No change to which fields mx-agent payloads carry; no introduction of any float-valued
  field. This is purely defensive.
- No general-purpose "normalize float to integer when whole" behavior — the issue lists
  normalization only as an alternative; the recommended approach is strict rejection (see
  Open Questions). Whole-valued floats (`1.0`) should also be rejected, not coerced.
- No change to non-interactive password sourcing (env var), to the auth/login flow, to the
  daemon, or to signing key management.
- No Windows support paths or assumptions (project is Unix-only).
- Not addressing the broader, separately-tracked hardening items #222 (signed
  call-request replay/expiry) or the general signing implementation #22.

## Relevant Repository Context
- **Workspace / crates.** `mx-agent-cli` owns the stateless CLI; `mx-agent-protocol` owns
  event schemas, canonical JSON, and signing. The CLI never holds Matrix tokens or device
  keys — the daemon does. These two fixes live in two different crates and are independent.
- **`read_password`** is at `crates/mx-agent-cli/src/cli.rs:1415-1430`. It checks
  `ENV_PASSWORD` (`MX_AGENT_PASSWORD`), and otherwise `eprint!`s `"Matrix password: "`,
  flushes stderr, and `stdin().read_line(...)`s with echo on. Its sole caller is
  `auth_login` (`cli.rs:1432+`), which treats an empty result as "no password provided".
- **Existing termios pattern to mirror.** `crates/mx-agent-cli/src/terminal.rs` already
  manipulates terminal modes through `rustix::termios` for interactive PTY exec. It defines
  a `RawModeGuard` that snapshots `Termios` via `tcgetattr`, mutates it, applies it with
  `tcsetattr(_, OptionalActions::Flush, _)`, and restores the original on `Drop`. Its tests
  reference `rustix::termios::LocalModes` (the bitflags that include `ECHO`). This is the
  canonical in-repo idiom for a scoped, RAII-restored terminal-mode change and should be
  followed closely (guard struct + `Drop` restore + `isatty` gate + graceful fallback when
  not a TTY).
- **`rustix` is already a dependency.** Root `Cargo.toml:40` enables
  `features = ["std", "pty", "termios"]`; `crates/mx-agent-cli/Cargo.toml:29` pulls it via
  `{ workspace = true }`. No new crate is needed. `mx-agent-protocol` has no rustix/termios
  involvement — its fix is pure Rust over `serde_json`.
- **`canonical_json`** (`crates/mx-agent-protocol/src/canonical_json.rs`) exposes
  `to_canonical_string(&Value) -> String` and `to_canonical_bytes(&Value) -> Vec<u8>`,
  both infallible today, plus the private recursive `write_value`. The number branch is
  line 42.
- **`signing`** (`crates/mx-agent-protocol/src/signing.rs`) is the only consumer of
  `to_canonical_bytes`. `signing_bytes` (line 76) already returns
  `Result<Vec<u8>, SignatureError>` and is called by `sign`, `sign_into`, and `verify`.
  The error enum `SignatureError` (lines 38-50) is the natural place to add a float-rejection
  variant. The module has a known-answer test vector (`known_answer_test_vector`) that pins
  the exact signed bytes and signature — integer encoding must remain byte-identical so that
  test keeps passing.
- **No other callers.** A workspace grep shows `to_canonical_string` / `to_canonical_bytes`
  / `signing_bytes` are used only inside `canonical_json.rs` and `signing.rs` (plus their
  tests). Changing the public signatures to fallible is therefore low-blast-radius, but see
  CLI/API Changes for the recommended non-breaking option.
- **Constraints (CLAUDE.md / architecture).** No `unsafe` (workspace forbids it; rustix is
  safe-wrapped). MSRV 1.74. Unix-only. Document new public APIs. Never log secrets; use the
  existing `Secret` patterns. Preserve human output by default and `--json` for automation.

## Proposed Implementation

### Part A — Disable echo in `read_password` (`mx-agent-cli`)
Wrap the interactive prompt's line read in a scoped guard that clears the terminal `ECHO`
local-mode flag and restores the original `Termios` on drop. Mirror `terminal.rs`'s
`RawModeGuard` shape, but clear only `ECHO` (and, conventionally, keep canonical mode on so
backspace/line editing still work) rather than calling `make_raw`.

Recommended structure:
1. Add a small helper in `cli.rs` (or a tiny private module) — e.g.
   `struct EchoOffGuard { original: Termios }` with:
   - `fn activate() -> Option<EchoOffGuard>`: operate on **stdin** (the fd the password is
     read from). If `!isatty(&io::stdin())`, return `None` (non-TTY: nothing to disable,
     read proceeds normally — important for piped/test input). Otherwise `tcgetattr`,
     clone, clear `LocalModes::ECHO` (consider also clearing `ECHONL` so a trailing newline
     is not echoed; leave `ICANON` set so the user can edit the line), apply with
     `tcsetattr(_, OptionalActions::Flush, _)`, and return the guard holding the original.
   - `impl Drop`: `tcsetattr` the saved original back with `OptionalActions::Flush`.
2. In `read_password`, after the env-var check and after `eprint!`/flush of the prompt,
   `let _guard = EchoOffGuard::activate();` then perform the existing
   `stdin().read_line(...)`. Because echo was suppressed, the user's Enter keystroke is also
   not echoed, so **manually print a newline to stderr** after the read (when a guard was
   active) so the next output is not glued onto the prompt line — match the conventional
   `getpass`/`rpassword` behavior.
3. The guard's `Drop` restores echo on the normal path, on the `?` error-return path of
   `read_line`, and on panic unwind, satisfying "restore echo on return/error/panic".
4. Do **not** add the heavyweight signal-restore thread from `terminal.rs`. That machinery
   exists because raw-mode PTY sessions are long-lived; a password read is a single blocking
   `read_line` with no event loop, and a `SIGINT` during it terminates the short-lived CLI
   immediately. (If desired, this can be reconsidered — see Open Questions — but it is not
   required for the acceptance criteria and adds complexity.)

Behavior to preserve verbatim: `MX_AGENT_PASSWORD` precedence and the
empty-string → "no password provided" semantics in `auth_login`; the password is never
placed in argv; the password string is returned to the caller exactly as today (trimmed of
trailing `\n`/`\r`).

### Part B — Reject floats in `canonical_json` (`mx-agent-protocol`)
Make canonical encoding fallible for floats and thread the error through signing.

Recommended approach (strict rejection, fallible API):
1. Define a small error type in `canonical_json.rs`, e.g.
   `#[derive(Debug, Clone, PartialEq, Eq)] pub enum CanonicalJsonError { NonIntegerNumber }`
   with `Display`/`Error` impls ("canonical JSON forbids non-integer numbers").
2. Change `write_value` to return `Result<(), CanonicalJsonError>` and, in the
   `Value::Number(n)` branch, reject when the number is not an integer:
   `if n.is_f64() { return Err(CanonicalJsonError::NonIntegerNumber); }` (a `serde_json`
   `Number` is `is_f64()` exactly when it is not representable as `i64`/`u64`, i.e. a float
   literal such as `1.0`, `3.14`, or a non-finite—`serde_json` already refuses NaN/Inf at
   parse time). Integers continue to emit `n.to_string()` unchanged.
3. Add fallible public wrappers: `to_canonical_string(&Value) -> Result<String, CanonicalJsonError>`
   and `to_canonical_bytes(&Value) -> Result<Vec<u8>, CanonicalJsonError>`. (See CLI/API
   Changes for the alternative non-breaking signatures.)
4. In `signing.rs`: add `SignatureError::NonCanonical` (or reuse a new variant) and map the
   `CanonicalJsonError` from `to_canonical_bytes` into it inside `signing_bytes`
   (`signing.rs:84`). `sign`, `sign_into`, and `verify` already propagate `signing_bytes`'
   `Result`, so a float-bearing content now produces a clean signing error instead of bytes
   that disagree with a strict Matrix peer. Update the `SignatureError` `Display` arm.
5. Update the `canonical_json` module doc comment (lines 7-13) to state explicitly:
   *numbers must be integers; floating-point values are rejected* — making the
   "same rules as Matrix canonical JSON" claim true.

Because integer/string encoding is byte-for-byte unchanged, the existing signing
known-answer vector and all canonical-json round-trip tests remain valid.

## Affected Files / Crates / Modules
- `crates/mx-agent-cli/src/cli.rs` — `read_password` (1415-1430); add `EchoOffGuard` helper;
  fix the `:1417` doc comment to remain accurate. Sole caller `auth_login` (1432+) — read
  only, no change expected.
- `crates/mx-agent-cli/src/terminal.rs` — read as the reference pattern (no change).
- `crates/mx-agent-cli/Cargo.toml` — confirm `rustix` (already present); no edit expected.
- `crates/mx-agent-protocol/src/canonical_json.rs` — float rejection, fallible API, new
  error type, module doc, new test.
- `crates/mx-agent-protocol/src/signing.rs` — thread the error through `signing_bytes`
  and `SignatureError`; add a float-rejection test.
- `docs/cli-reference.md` (337, 361) — claims already say "not echoed"; verify they are now
  accurate (likely no edit beyond confirmation).

## CLI / API Changes
- **CLI surface:** none. No new flags, subcommands, env vars, or output-format changes. The
  only observable difference is that typed password characters are no longer shown at the
  `Matrix password:` prompt (the documented, expected behavior).
- **Public Rust API (`mx-agent-protocol`):** `to_canonical_string` and `to_canonical_bytes`
  change from infallible to fallible. There are no out-of-crate callers, so this is safe,
  but it is a public-signature change.
  - *Recommended:* make them return `Result<_, CanonicalJsonError>` and document the new
    error type (CLAUDE.md requires documenting new public APIs).
  - *Alternative (fully non-breaking):* keep the infallible names delegating to new
    `try_canonical_string`/`try_canonical_bytes`, having the infallible variants `expect`
    on integer-only inputs — **not recommended**, since a panic in the signing path is worse
    than a typed error. Prefer the fallible signatures and update the two internal callers.
  - `signing_bytes`/`sign`/`sign_into`/`verify` keep their existing `Result<_, SignatureError>`
    signatures; only a new error variant is added.

## Data Model / Protocol Changes
None to the wire format. No event schema, persistence, or policy change. The canonical-JSON
byte output for all currently-used (integer/string/bool/null/array/object) payloads is
byte-identical to today; the change only adds a rejection for a value kind mx-agent never
emits. This is a *tightening* of the existing signing contract, not a format change, so it
does not affect interoperability for current payloads.

## Security Considerations
- **Secret handling (Part A).** The password is a secret; suppressing echo removes a
  shoulder-surf / scrollback / `script(1)` transcript leak. The guard must restore echo on
  every exit path (normal, error, panic) so a failed login cannot strand the user's terminal
  echo-less — `Drop`-based restore (as in `terminal.rs`) provides this. Continue to never
  log the password and never place it in argv; the returned value is handed to the existing
  flow that wraps the session token as `Secret`.
- **Non-TTY fallback (Part A).** When stdin is not a TTY (pipe, here-doc, test harness),
  `activate()` returns `None` and the read proceeds normally — preserving scriptability and
  avoiding an error on systems/contexts without a controlling terminal. This is the same
  `isatty` gate `terminal.rs` uses.
- **Signing integrity (Part B).** `canonical_json` produces the exact bytes Ed25519 signs.
  Rejecting floats prevents a future float field from being signed over bytes that a strict
  Matrix verifier would compute differently — i.e. it forecloses a silent signature-agreement
  divergence between peers. Failing closed (returning an error rather than emitting
  non-canonical bytes) is the security-correct choice: a privileged request that cannot be
  canonicalized must not be signed or accepted.
- **Daemon/CLI separation.** Unchanged. Part A is entirely in the stateless CLI; the CLI
  still never sees tokens or device keys. Part B is in the shared protocol crate used by
  both sides identically, preserving symmetric sign/verify.
- **Unix-only / no `unsafe`.** rustix termios calls are safe wrappers; no `unsafe` is
  introduced. No Windows paths added.

## Testing Plan
- **`canonical_json.rs` unit tests (add):**
  - `float_number_is_rejected`: `to_canonical_string(&json!({"x": 1.5}))` returns
    `Err(CanonicalJsonError::NonIntegerNumber)` (and the bytes variant likewise).
  - `whole_valued_float_is_rejected`: `json!(1.0)` is rejected, not coerced to `"1"`.
  - `integers_still_encode`: regression guard that `json!(42)`, `json!(-7)`, and large
    `u64`/`i64` values still encode to their decimal strings (extends/keeps
    `scalars_round_trip`).
  - Update existing infallible-asserting tests to unwrap the new `Result`.
- **`signing.rs` unit tests (add):**
  - `float_content_fails_to_sign`: `sign(&key, "k", &json!({"amount": 1.5}))` returns the
    mapped `SignatureError` variant; `signing_bytes` on the same content errors.
  - Confirm `known_answer_test_vector` and `signing_is_deterministic_*` still pass unchanged
    (proves integer canonicalization is byte-stable).
- **`read_password` (Part A):**
  - Logic-level unit test for the env-var path: with `MX_AGENT_PASSWORD` set, `read_password`
    returns it without touching the terminal (no TTY interaction). Use a serialized/guarded
    env mutation to avoid cross-test races.
  - The echo-suppression itself requires a real TTY and cannot run reliably in CI; document a
    **manual acceptance test** in a doc comment near `read_password` (mirroring the manual
    test block in `terminal.rs`): run `mx-agent auth login` with `MX_AGENT_PASSWORD` unset,
    type at the `Matrix password:` prompt, and confirm characters are not echoed and that the
    shell prompt afterward has normal echo. Optionally add a non-CI-gated test that opens
    `/dev/tty`, toggles `ECHO` via the guard, and asserts the flag is cleared then restored —
    skipped when no tty is available (same pattern as `terminal.rs` tests).
- **Workspace gates:** `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`,
  and `cargo fmt --check` must pass. MSRV 1.74 respected.

## Documentation Updates
- `crates/mx-agent-cli/src/cli.rs:1417` — keep/refine the doc comment so it accurately
  reflects that the interactive prompt now suppresses echo; optionally add a one-line manual
  acceptance note.
- `crates/mx-agent-protocol/src/canonical_json.rs` module header — add the explicit
  integer-only / floats-rejected contract bullet.
- Document the new public error type and the now-fallible `to_canonical_string` /
  `to_canonical_bytes` (rustdoc), and the new `SignatureError` variant.
- `docs/cli-reference.md:337,361` — verify the existing "not echoed" wording is now correct;
  edit only if it needs sharpening. No status-table or roadmap change required (this is
  hardening of existing behavior, not a new feature).

## Risks and Open Questions
- **Reject vs. normalize floats.** The issue allows either strict rejection or normalization.
  Recommendation: **reject** (fail closed). Normalizing `1.0 → 1` would silently alter a
  signer's intent and still leaves genuine fractional values unrepresentable; rejection is
  simpler and matches "Matrix forbids floats". Confirm this choice before implementing.
- **Public API breakage tolerance.** Making `to_canonical_string`/`to_canonical_bytes`
  fallible is the clean design but changes a public signature. Given there are no
  out-of-crate callers, this is low risk; confirm whether the project prefers the fallible
  signatures (recommended) or wrapper-preserving names.
- **Signal handling during the prompt.** Unlike PTY raw mode, the password read does not
  install a signal-restore thread. If a `SIGINT`/`SIGTSTP` arrives mid-read, the process is
  interrupted before `Drop` may run, potentially leaving echo off. For a single short
  blocking read this is a minor, conventional trade-off (matches common `getpass`
  implementations), but flag it: if stronger guarantees are wanted, the `terminal.rs`
  signal-restore approach could be reused. Decide whether that complexity is warranted.
- **`ECHONL` / newline handling.** With echo off, the Enter keypress is not echoed; the
  implementation must emit a newline to stderr after the read so subsequent output is not
  appended to the prompt line. Verify the resulting output is clean in both human and
  `--json` modes (the prompt and newline go to stderr, not stdout, so `--json` on stdout is
  unaffected).
- **`serde_json` integer edge cases.** Confirm `Number::is_f64()` is the correct
  discriminator across the `arbitrary_precision` feature setting (mx-agent uses default
  features, where `is_f64()` reliably distinguishes floats from `i64`/`u64`). Large integers
  beyond `i64`/`u64` are not representable by `serde_json` without `arbitrary_precision`, so
  no additional handling is needed under current features.

## Implementation Checklist
1. **Part B — protocol (do first; smaller blast radius, unblocks signing tests):**
   1. Add `CanonicalJsonError` (with `Display` + `std::error::Error`) to `canonical_json.rs`.
   2. Change `write_value` to return `Result<(), CanonicalJsonError>`; reject `n.is_f64()`
      in the `Value::Number` branch; propagate `?` through array/object recursion.
   3. Make `to_canonical_string`/`to_canonical_bytes` return `Result<_, CanonicalJsonError>`;
      update their rustdoc and the module header to state the integer-only contract.
   4. Add `SignatureError::NonCanonical` (or similarly named) variant + `Display` arm;
      map the canonical-json error inside `signing_bytes` (`signing.rs:84`).
   5. Update the two internal callers and existing tests to handle the new `Result`s.
   6. Add `float_number_is_rejected`, `whole_valued_float_is_rejected`,
      `integers_still_encode` (canonical_json) and `float_content_fails_to_sign` (signing);
      confirm `known_answer_test_vector` still passes.
2. **Part A — CLI:**
   1. Add an `EchoOffGuard` (RAII) helper near `read_password`, modeled on
      `terminal.rs::RawModeGuard`: `activate()` gated on `isatty(stdin)`, clears
      `LocalModes::ECHO` (and `ECHONL`) via `tcgetattr`/`tcsetattr`, `Drop` restores.
   2. In `read_password`, acquire the guard after printing the prompt, perform the existing
      `read_line`, emit a trailing newline to stderr when a guard was active, return the
      trimmed password. Preserve `MX_AGENT_PASSWORD` precedence and empty-input semantics.
   3. Refine the `:1417` doc comment / add the manual acceptance note.
   4. Add the env-var-path unit test (serialized env mutation) and, optionally, the
      `/dev/tty` ECHO-toggle test gated on `isatty`.
3. **Verification:** run `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`,
   `cargo test --workspace`; manually verify no-echo at the prompt on a real TTY and that the
   shell echo is intact afterward.
4. **Docs:** confirm `docs/cli-reference.md` "not echoed" wording is accurate; ensure all new
   public items are documented.
