# Issue #269 — Reconcile the `auth`/`trust` CLI-local carve-out with the docs, and serialize concurrent session/key writes

## Problem Statement

The project's stated token-isolation model is that the stateless CLI never owns
Matrix credentials and never builds or restores a Matrix client: `auth login` is
CLI-initiated *only* to receive the password and hand it to the daemon, and the
daemon owns all long-lived secrets (session token, crypto store, signing key).
Four pieces of documentation assert this as an enforced, fully-IPC-mediated
boundary.

In the current tree that boundary is **not** enforced for the `auth` and `trust`
command groups, and the docs overstate it:

- `auth login` (`crates/mx-agent-cli/src/cli.rs:1516`) calls
  `mx_agent_daemon::login_password` **in the CLI process**, which
  (`crates/mx-agent-daemon/src/matrix.rs:280` → `build_client_with_store`
  `matrix.rs:196`) builds a full **store-backed Matrix client**, performs the
  network login, and **creates the daemon-owned E2EE crypto store** (`0700` dir
  at `session.rs:189`, `0600` passphrase at `session.rs:224`) plus the device
  identity; it then calls `save_session` (`cli.rs:1559`, `session.rs:247`) itself.
- `auth status`/`auth logout` (`cli.rs:1579` / `cli.rs:1612`) and `trust`
  `list`/`approve`/`revoke`/`fingerprint` (`cli.rs:1656` / `1692` / `1725` /
  `1892`) all run **locally** against `session.json` / `trust.json`. In
  particular `trust fingerprint` calls `load_or_create_signing_key`
  (`signing.rs:156`) and can **create the daemon's Ed25519 signing key**
  (`0600`, `signing.rs:176`) from the CLI process.
- There is **no `auth.*` method in the IPC dispatch table**
  (`lifecycle.rs:540`+); only `trust.publish` and `trust.state` are
  daemon-IPC-mediated.

**Important nuance:** `mx-agent-cli` depends on `mx-agent-daemon` as a *library*
and the two ship as the **same binary**, so these are in-process library calls at
the **same UID**, not a crossing of a separate privilege boundary.
`docs/architecture.md` (§10.3) already documents `auth login` as an accepted
CLI-initiated carve-out, and issue #201 deliberately **deferred** adding an
`auth.login` IPC (to avoid creating a new password-over-socket credential
surface) — see `specs/issue-201-cli-command-groups-behind-ipc.md`.

So the real defects are:

1. **Docs/security-model drift (security-relevant):** `README.md`,
   `docs/user-guide.md`, `docs/security-hardening.md`, and the
   `crates/mx-agent-daemon/src/ipc.rs` module doc each assert, without
   qualification, that the CLI "never builds a Matrix client" / "never handles
   secrets directly" / that **every** Matrix-backed command (explicitly
   including `auth` and `trust`) is daemon-IPC-mediated. A reader auditing the
   token-isolation model is told the boundary is enforced over IPC when, for
   `auth login`, the CLI process reads the password, builds the client, and
   creates/holds the crypto-store passphrase and (via `trust fingerprint`) the
   Ed25519 signing key in-process. This contradicts `architecture.md`.

2. **Unlocked concurrent mutation:** running a CLI-local `auth login` while a
   daemon is already running mutates the shared `session.json`, crypto-store key,
   and signing key with **no advisory lock**. The in-process `ACTIVE_CLIENTS`
   dedup (`matrix.rs:341`) is a process-local `OnceLock<RwLock<HashMap>>` and
   cannot span processes, so two `mx-agent` processes can race the
   store/key/session writes with no coordination.

## Goals

- Make the four overstated docs **accurately describe** the existing accepted
  CLI-local carve-out for `auth login` (and the locally-run `auth status`/
  `logout` and `trust list`/`approve`/`revoke`/`fingerprint`), so they agree with
  `docs/architecture.md §10.3`. Remove or qualify the blanket "CLI never builds a
  Matrix client / never handles secrets directly / every command is
  daemon-IPC-mediated" wording.
- Tighten `architecture.md §10.3` itself so the canonical carve-out also states
  explicitly that the CLI *builds a store-backed client and creates the crypto
  store + signing key in-process* for these commands (today it only says the CLI
  "receives the password and writes the session").
- Add a cross-process **advisory file lock** around `save_session`,
  crypto-store-key creation, and signing-key creation so a CLI-local `auth login`
  (or `trust fingerprint`) cannot race a running daemon's writes to the same
  files. Add a deterministic test proving two concurrent writers serialize and
  converge on a single consistent key.
- Keep human-readable default output and `--json` output for every touched
  command **unchanged** (this issue changes docs + an internal lock, not command
  output).

## Non-Goals

- **Not** implementing option (a) "real `auth.login` IPC mediation" in this
  change. That would reverse the deliberate #201 deferral and introduce a new
  password-over-socket credential surface plus dynamic worker (re)start after
  login; it is documented below as an alternative and flagged for maintainer
  decision, but the recommended scope is the docs reconciliation + advisory lock.
  Do **not** add `auth.*` to the dispatch table or method table under the
  recommended scope.
- No change to the Matrix wire protocol, event schema, signing, trust, or policy
  semantics.
- No change to `trust publish` / `trust state`, which are already
  daemon-IPC-mediated and correct.
- No new CLI flags, subcommands, or output-shape changes.
- Unix-only; no Windows paths or assumptions are introduced.

## Relevant Repository Context

- **Same-binary architecture.** `mx-agent-cli` links `mx-agent-daemon` as a
  library; the `mx-agent` binary is both CLI and daemon. CLI handlers that touch
  Matrix state call `mx_agent_daemon::*` functions directly. The privilege model
  is "same user, same binary," so the `auth`/`trust` carve-out is an in-process
  call, not a boundary breach — but the docs must say so.
- **Daemon ownership of secrets** (`docs/security-hardening.md`,
  `architecture.md §13`): session token (`session.json`, `0600`), crypto store
  (`crypto-store/`, `0700`, passphrase `crypto-store-key`, `0600`), Ed25519
  signing key (`signing_key.ed25519`, `0600`), trust store (`trust.json`,
  `0600`) — all under the data dir (`~/.local/share/mx-agent`, `0700`; override
  `MX_AGENT_DATA_DIR`). `SessionPaths::resolve()` is env-derived;
  `SessionPaths::for_data_dir(dir)` is used by tests/tooling.
- **IPC mediation pattern** (`lifecycle.rs`): the dispatch table maps a method
  name to `parse_params::<P>()` + `block_on_task_response(req, |session| async
  { … })`. `block_on_task_response` first calls `load_daemon_session_response`
  (returns the JSON-RPC error `"not logged in; run 'mx-agent auth login' first"`
  when no session exists). The CLI side uses `daemon_ipc_call::<P, R>(global,
  "method", &params)`. This is the established shape any future `auth.*` method
  would follow.
- **Worker lifecycle** (`lifecycle.rs:311` `spawn_matrix_workers`): the sync,
  scheduler, and heartbeat threads are spawned **once at daemon start** and only
  if a session already exists on disk. There is currently **no mechanism to
  (re)spawn them after a login that happens while the daemon is running** — which
  is exactly why option (a) is a larger change than it looks, and why a CLI-local
  re-login does not refresh a running daemon's client.
- **Write helpers to protect:**
  - `session.rs:247 save_session` — atomic write-to-temp + rename of
    `session.json` (`0600`). Caller: `cli.rs:1559` (login).
  - `session.rs:207 load_or_create_crypto_store_key` →
    `session.rs:224 generate_crypto_store_key` — atomic write-to-temp + rename of
    `crypto-store-key` (`0600`). Caller path: `matrix.rs:205`
    (`build_client_with_store`, reached by both login and `restore_client`).
  - `signing.rs:156 load_or_create_signing_key` →
    `signing.rs:176 generate_and_store` — atomic write-to-temp + rename of
    `signing_key.ed25519` (`0600`). Callers: `trust fingerprint` (CLI) **and**
    many daemon paths (exec/call/agent/approval/task-cancel/scheduler signing).
  - All three already use write-to-temp-then-rename, so a *torn* file is not the
    risk; the risk is a **lost update** when two processes both observe "key
    absent," both generate, and one clobbers the other — after which a client
    that encrypted the store under the discarded passphrase can no longer open it.
- **No existing advisory-lock infra.** Double-start is prevented only by the
  `daemon.json` status file + `is_alive(pid)` check (`lifecycle.rs`), not a
  `flock`. `nix` is a daemon dependency with features `["signal","process",
  "user"]` (no `fcntl`); `rustix` is a workspace dep with features
  `["std","pty","termios"]` (no `fs`). Adding `flock` requires enabling one
  feature (details below). `unsafe` is forbidden workspace-wide, so use a safe
  wrapper (`nix::fcntl::Flock` or `rustix::fs::flock`).
- **Overstated doc locations (to fix):**
  - `README.md:45` — status-table row: "`auth`, `workspace`, `agent`, `trust`,
    `approval`, `share`, `invocation` commands fully daemon-IPC-mediated (CLI
    never restores a Matrix session/client)".
  - `README.md:96` — Quickstart paragraph: "the stateless CLI never reads the
    Matrix session file or builds a Matrix client itself (`auth login` stays
    CLI-initiated …)".
  - `docs/user-guide.md:7-11` — alpha-status note: "The workspace, auth, …, and
    invocation commands run … entirely through the daemon over local IPC — the
    stateless CLI never reads the Matrix session or builds a Matrix client
    itself."
  - `docs/security-hardening.md:63` — token-isolation section: "The daemon owns
    all long-lived secrets; the CLI never handles them directly."
  - `crates/mx-agent-daemon/src/ipc.rs:1-11` — module doc: "The stateless CLI
    must never restore Matrix sessions or build Matrix clients itself … every
    Matrix-backed command is sent to the daemon …".
- **Already-correct reference:** `docs/architecture.md §10.3` (the paragraph
  beginning "Every Matrix-backed command group is daemon-mediated …" and its
  method table) already carves out `auth login` / `auth status` / `auth logout`.
  Mirror its language; extend it slightly per the Goals.

## Proposed Implementation

Recommended scope = **(b) accurate docs + advisory lock**. Implement both parts.

### Part 1 — Cross-process advisory write lock (`mx-agent-daemon`)

1. **Add a lock-file path.** In `session.rs`, extend `SessionPaths` with a lock
   path derived from `data_dir`, e.g. add `lock_file: data_dir.join(".write.lock")`
   to both `resolve()` and `for_data_dir()` (or expose a
   `pub fn write_lock_path(&self) -> &Path`). The lock file lives in the same
   data dir as the secrets it guards, so a test temp dir and a real daemon never
   contend, and a `MX_AGENT_DATA_DIR` override scopes the lock correctly.

2. **Add a lock guard helper** in `session.rs` (documented public item — see
   "Document new public APIs"):

   ```rust
   /// Hold a cross-process advisory exclusive lock for the duration of a write
   /// to the daemon-owned data dir (session, crypto-store key, signing key).
   ///
   /// The lock is `flock(LOCK_EX)` on `<data_dir>/.write.lock` (created `0600`).
   /// It serializes a CLI-local `auth login` / `trust fingerprint` against a
   /// running daemon so two processes cannot lost-update the same key/session
   /// file (issue #269). Advisory and Unix-only; released on drop.
   fn with_data_dir_write_lock<T>(
       paths: &SessionPaths,
       f: impl FnOnce() -> io::Result<T>,
   ) -> io::Result<T>
   ```

   Implementation: `ensure_data_dir()`; open/create the lock file (`0600`);
   acquire an exclusive advisory lock; run `f`; the guard drops (unlocks) on
   return/error. Use `nix::fcntl::Flock::lock(file, FlockArg::LockExclusive)`
   (RAII; add the `fcntl` feature to `mx-agent-daemon`'s `nix`) **or**
   `rustix::fs::flock(&file, FlockOperation::LockExclusive)` (add the `fs`
   feature to the workspace `rustix`). No `unsafe` either way. Keep the helper
   private to the module; expose behavior only through the three write functions
   below so all callers (CLI included, since they call into this crate) get it
   automatically.

3. **Wrap the write/create critical sections — never the hot read path:**
   - `save_session`: wrap its body in `with_data_dir_write_lock` (login only; cheap).
   - `generate_crypto_store_key`: acquire the lock, then **re-check** the key file
     under the lock (double-checked): if it now exists, return the existing key;
     else generate + rename. Keep the steady-state `load_or_create_crypto_store_key`
     read path **lock-free** (an atomically-renamed file reads safely); only the
     NotFound/create branch takes the lock and re-reads.
   - `generate_and_store` (signing): same double-checked pattern — acquire lock,
     re-check `signing_key_file` existence, generate + rename only if still
     absent. Keep `load_or_create_signing_key`'s common read path lock-free so the
     daemon's many per-operation signing reads are not serialized.

   This guarantees **no nested lock acquisition** (login calls
   `build_client_with_store` then `save_session` sequentially, each taking and
   releasing the lock independently), so there is no self-deadlock. The lock is
   held only on infrequent create/write paths.

4. **Behavior preserved:** return types, error types, file modes (`0600`/`0700`),
   and the atomic write-to-temp-then-rename all stay identical. The lock only
   adds mutual exclusion.

### Part 2 — Docs reconciliation

Bring the five overstated locations into line with `architecture.md §10.3`,
stating the accepted CLI-local exception precisely. Suggested replacement intent
(adapt wording to each doc's voice; do not invent new behavior):

- **`README.md:45`** — qualify the status row, e.g. change "`auth`, `workspace`,
  …, `invocation` commands fully daemon-IPC-mediated (CLI never restores a Matrix
  session/client)" to scope the "fully daemon-IPC-mediated" claim to
  `workspace`/`agent`/`approval`/`share`/`invocation` (and `trust publish`/
  `state`), and note that **`auth login` is a CLI-initiated exception** that
  builds a store-backed client and creates the crypto store in-process, and that
  `auth status`/`logout` and `trust list`/`approve`/`revoke`/`fingerprint` are
  CLI-local.
- **`README.md:96`** — replace "the stateless CLI never reads the Matrix session
  file or builds a Matrix client itself" with the accurate statement: the CLI
  never reads the session for the daemon-mediated groups, **but** `auth login`
  builds a store-backed Matrix client and creates the daemon-owned crypto store
  in-process, and `auth status`/`logout` + local `trust` commands read/write
  `session.json`/`trust.json`/`signing_key.ed25519` directly (same-binary,
  same-UID). Keep the existing "receive the password and hand the session to the
  daemon" framing.
- **`docs/user-guide.md:7-11`** — drop `auth` (and the unqualified `trust`) from
  the "entirely through the daemon over local IPC" list and the "never reads the
  Matrix session or builds a Matrix client itself" clause; add a one-sentence
  carve-out matching architecture.md.
- **`docs/security-hardening.md:63`** — change "The daemon owns all long-lived
  secrets; the CLI never handles them directly" to acknowledge the exception:
  the daemon owns the secrets at rest, but for `auth login` (and `trust
  fingerprint`/local `trust`) the **same-binary CLI process** reads the password,
  builds the client, and creates/reads the crypto-store passphrase and signing
  key in-process — an accepted same-UID exception, not a separate privilege
  boundary. Reference architecture.md §10.3.
- **`crates/mx-agent-daemon/src/ipc.rs:1-11`** — soften "every Matrix-backed
  command is sent to the daemon … the CLI must never restore Matrix sessions or
  build Matrix clients itself" to "every Matrix-backed command group **except the
  `auth`/`trust` carve-out** (see architecture.md §10.3)". This is a `//!` doc
  comment, so the wording must remain accurate for the methods defined in that
  module.
- **`docs/architecture.md §10.3`** (canonical reference) — extend the existing
  carve-out paragraph to add that the CLI, for `auth login`, **builds a
  store-backed Matrix client and creates the daemon-owned crypto store +
  (via `trust fingerprint`) signing key in-process**, and that this is safe only
  because CLI and daemon are the same binary at the same UID. Add a sentence
  noting the advisory lock now serializes those in-process writes against a
  running daemon. Do **not** add `auth.*` to the method table (no such method
  exists under the recommended scope).

Cross-check there are no other copies of the blanket claim (e.g. `wiki/`
pages, `docs/alpha-release-checklist.md`); fix any that surface, but scope to
the listed files unless a `grep` shows an exact duplicate of the overstated
sentence.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/session.rs` — add lock path + `with_data_dir_write_lock`;
  wrap `save_session`, `generate_crypto_store_key`; add the concurrency unit test.
- `crates/mx-agent-daemon/src/signing.rs` — wrap `generate_and_store` (double-checked).
- `crates/mx-agent-daemon/Cargo.toml` — enable `nix` `fcntl` (or workspace
  `rustix` `fs`) feature for `flock`.
- `Cargo.toml` (workspace) — only if choosing the `rustix` `fs` route.
- `README.md` — lines ~45 and ~96.
- `docs/user-guide.md` — lines ~7-11.
- `docs/security-hardening.md` — line ~63 (token-isolation section).
- `docs/architecture.md` — §10.3 carve-out paragraph.
- `crates/mx-agent-daemon/src/ipc.rs` — module doc (`//!`, lines 1-11).
- Read-only for accuracy: `crates/mx-agent-cli/src/cli.rs`
  (`auth_login`/`auth_status`/`auth_logout`/`trust_*`), `crates/mx-agent-daemon/src/matrix.rs`
  (`login_password`/`build_client_with_store`/`ACTIVE_CLIENTS`),
  `crates/mx-agent-daemon/src/lifecycle.rs` (dispatch table, `spawn_matrix_workers`).

## CLI / API Changes

- **CLI surface:** none. No new flags, subcommands, output shape, or exit-code
  changes; `auth`/`trust` commands behave and print exactly as before.
- **Public Rust API:** one new documented item in the daemon crate
  (`with_data_dir_write_lock`, or a `DataDirWriteLock` RAII guard) plus possibly a
  new `SessionPaths::write_lock_path()` accessor. `missing_docs` is denied in CI,
  so document any new `pub` item; prefer keeping the lock helper module-private
  and only the path accessor public if one is needed.
- **IPC / protocol:** none under the recommended scope (no new methods). See the
  alternative below for the option-(a) surface that is intentionally **not** added.

## Data Model / Protocol Changes

None. No event schema, persistence format, policy, or serialization changes. A
new zero-length `<data_dir>/.write.lock` file is created for `flock`, but it
stores no data and is not part of any protocol.

## Security Considerations

- **Secret handling unchanged.** The crypto-store passphrase and signing key
  remain `Secret`/`0600`; the lock file holds no secret bytes. No new logging of
  tokens, passwords, or keys; keep `mx_agent_telemetry::Secret`/redaction.
- **Daemon/CLI separation is documented, not newly broken.** This change does not
  move secrets into the CLI — they are already created there for `auth login`.
  The deliverable is to make the docs *truthful* about the existing same-binary,
  same-UID exception so a security auditor is not misled. Preserve the
  zero-trust execution invariants verbatim: room membership ≠ execution rights;
  privileged requests stay Ed25519-signed and checked against deny-by-default
  local policy; the coding agent still never sees tokens or device keys (the
  agent runs as a child of the daemon, not as the interactive operator who runs
  `auth login`).
- **Concurrency hazard reduced.** The advisory lock prevents two `mx-agent`
  processes from lost-updating the crypto-store key (the most damaging race:
  losing the passphrase that decrypts the persistent store) and from interleaving
  `session.json`/signing-key writes. Note the lock is **advisory** (`flock`) and
  Unix-only; it coordinates mx-agent's own writers, not arbitrary external
  processes. It does **not** make a CLI-local re-login refresh a running daemon's
  in-memory client/session — call that out as a known limitation (option (a)
  territory), do not imply it is fixed.
- **No `unsafe`.** Use `nix::fcntl::Flock`/`rustix::fs::flock` safe wrappers;
  respect MSRV 1.74 (both are available on the pinned versions).
- **Unix only.** `flock` and the `0600`/`0700` modes are already Unix-gated;
  add no Windows branches.

## Testing Plan

- **Unit (default `cargo test`, no homeserver) — core deliverable:** in
  `session.rs`, a deterministic concurrency test that spawns two threads (each
  with its **own** `flock` fd) calling `load_or_create_crypto_store_key` on the
  same `for_data_dir` temp dir concurrently, and asserts both return the
  **identical** passphrase and exactly one key file exists — proving the
  double-checked create is atomic. Without the lock this can return two different
  keys (lost update); with it, it serializes. Reuse the existing `env_lock()` /
  `TempData` test scaffolding pattern already in `session.rs`/`signing.rs`.
- **Unit:** an analogous test for `signing.rs` `load_or_create_signing_key`
  (two concurrent creators converge on one fingerprint), and a `save_session`
  test where two threads repeatedly save distinct sessions and the final file
  always parses to one of the two valid sessions (no torn/partial JSON).
- **Regression:** confirm the existing `session.rs`/`signing.rs` unit tests
  (single-writer create/reload, fingerprint stability) still pass — the lock must
  not change single-process behavior.
- **Docs verification:** `grep` the repo to confirm no remaining unqualified
  "CLI never builds a Matrix client" / "never handles them directly" / "every
  Matrix-backed command … through the daemon" sentence that contradicts the
  carve-out; verify each edited doc still reads coherently.
- **CI gates:** `cargo fmt --check`, `cargo clippy --all-targets --all-features
  -- -D warnings` (no new `missing_docs`), `cargo test --all`, `cargo build
  --all`. No new `#[ignore]` live-Matrix test is required for this change.

## Documentation Updates

- `README.md` (status table row ~45; Quickstart paragraph ~96).
- `docs/user-guide.md` (alpha-status note ~7-11).
- `docs/security-hardening.md` (token-isolation section ~63).
- `docs/architecture.md` (§10.3 carve-out paragraph — tighten/extend).
- `crates/mx-agent-daemon/src/ipc.rs` module doc (~1-11).
- Doc comments for any new `pub` item in `session.rs`.
- Check `wiki/` and `docs/alpha-release-checklist.md` for duplicate overstated
  claims; fix only exact duplicates of the listed sentences.

## Risks and Open Questions

- **Direction decision (needs maintainer confirmation).** This spec recommends
  **(b) document the exception + add the lock**, consistent with the #201
  deferral and the same-binary reality. The issue also offers **(a) real
  `auth.login`/`auth.status`/`auth.logout` IPC mediation**. Option (a) is a
  materially larger change: it adds a password-over-socket surface, requires the
  daemon to perform `login_password` + `save_session` + crypto-store creation,
  and — critically — requires the daemon to **(re)spawn its sync/scheduler/
  heartbeat workers after a login that happens while it is already running**,
  which `spawn_matrix_workers` does not currently support (workers are spawned
  once at start, only if a session already exists). Given the same-UID,
  same-binary model, option (a) adds limited *privilege* isolation (no new
  boundary) at significant complexity and risk. If the maintainer wants the
  stated model to become literally true, (a) is the path — but it should be its
  own issue/PR, and the advisory lock from this spec is still required as an
  interim measure. Do not implement (a) without explicit sign-off.
- **flock dependency feature.** Choosing `nix` `fcntl` vs `rustix` `fs` is an
  implementation detail; pick the one that adds the smaller feature surface
  (`nix` `fcntl` keeps the change inside the daemon crate; `rustix` `fs` touches
  the shared workspace feature set). Confirm the chosen API exists on the pinned
  version (nix 0.31 `nix::fcntl::Flock`; rustix 1.x `rustix::fs::flock`).
- **Advisory-lock scope.** `flock` is advisory and coordinates only mx-agent's
  own writers; an unrelated process could still clobber the files. That matches
  the threat model (single-user, `0700` data dir) and the issue's ask; note it in
  the architecture/security docs rather than over-promising.
- **Known limitation to state, not fix:** a CLI-local `auth login` while a daemon
  is running creates a *new* device/session/crypto store, and the running daemon
  keeps using its old in-memory client until restarted. The lock prevents file
  corruption/lost-update but not this logical staleness. Surface this as a
  documented limitation (resolved only by option (a)).
- **`trust fingerprint` first-run side effect.** It can still create the signing
  key from the CLI; the lock makes that safe against a concurrent daemon, and the
  docs now state it. No behavioral change is proposed (leaving it CLI-local is
  consistent with the carve-out).

## Implementation Checklist

1. Read `session.rs`, `signing.rs`, `matrix.rs` (login path), and the five doc
   locations to confirm current wording and line numbers (they drift from the
   issue's snapshot).
2. Add the lock-file path to `SessionPaths` (`resolve()` + `for_data_dir()`),
   e.g. `lock_file`/`write_lock_path()`.
3. Enable the `flock` dependency feature (`nix` `fcntl` in
   `crates/mx-agent-daemon/Cargo.toml`, or `rustix` `fs` in the workspace
   `Cargo.toml`) and confirm it builds at MSRV.
4. Implement the documented `with_data_dir_write_lock` helper (or a
   `DataDirWriteLock` RAII guard) using a safe `flock` wrapper; no `unsafe`.
5. Wrap `save_session` in the lock; convert `generate_crypto_store_key` and
   `generate_and_store` (signing) to the **double-checked under-lock** create
   pattern, keeping the steady-state read paths lock-free. Verify no nested lock
   acquisition (login → build client → save_session are sequential).
6. Add the deterministic two-thread concurrency unit tests for crypto-store key,
   signing key, and `save_session`; reuse `env_lock()`/`TempData` scaffolding.
   Confirm existing single-writer unit tests still pass.
7. Edit the five docs (`README.md` ×2, `docs/user-guide.md`,
   `docs/security-hardening.md`, `crates/mx-agent-daemon/src/ipc.rs` module doc)
   to accurately describe the CLI-local `auth`/`trust` exception; remove/qualify
   the blanket claims.
8. Tighten/extend `docs/architecture.md §10.3` as the canonical carve-out
   (CLI builds client + creates crypto/signing material in-process; advisory lock
   serializes those writes). Do not add `auth.*` to the method table.
9. `grep` for any remaining duplicate of the overstated sentences (incl. `wiki/`,
   `docs/alpha-release-checklist.md`); fix exact duplicates only.
10. Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
    `cargo test --all`, `cargo build --all`; ensure no new `missing_docs`.
11. In the PR description, explicitly note: scope is option (b) + advisory lock;
    option (a) (real `auth.*` IPC) is deferred and flagged for maintainer
    decision; the daemon-staleness-after-CLI-relogin limitation is documented,
    not fixed.
