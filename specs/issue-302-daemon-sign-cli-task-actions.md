# Daemon-Side Signing of CLI-Authored Task Actions

> Issue: #302 — *No production path signs task actions: CLI-created tool/exec tasks are blocked as unsigned by the scheduler.*
> Labels: `type:feature` `area:daemon` `area:security` `area:tasks` `priority:p0`
> Spec status: planning only — **do not implement from this document in the planning phase.**

## Problem Statement

The flagship orchestration loop (auto-claim → dispatch → execute) is a dead end for every task a user can actually create today.

- `mx-agent task create` / `task update` build `TaskAction::Tool` / `TaskAction::Exec` with `authorization: None` hardcoded (`crates/mx-agent-cli/src/cli.rs:3893`, `cli.rs:3911`). There is no flag or code path to attach an authorization, and per the architecture's auth/trust carve-out (§10.3) the **CLI must never hold the daemon's signing key**, so the CLI cannot sign either.
- The daemon's `task.create` / `task.update` IPC handlers pass options through unchanged (`crates/mx-agent-daemon/src/lifecycle.rs:573-584` → `create_task_for_session` / `update_task_for_session` at `crates/mx-agent-daemon/src/task.rs:457`, `task.rs:532`); the action is copied verbatim into published room state (`task.rs:252`, `task.rs:283-285`). No signing happens anywhere on this path.
- The production scheduler **always** loads and configures a trust store (`scheduler_loop.rs:583`, wired via `build_scheduler_orchestrator` at `scheduler_loop.rs:532-557` with `.with_trust_store(trust)` at `scheduler_loop.rs:548`). With a trust store configured, `verify_task_action_authorization` requires a signed `TaskActionAuthorization` and blocks every unsigned action with reason `unsigned` (`task_orchestrator.rs:874-876`).
- The only producer of a valid authorization, `sign_task_action` (`task_orchestrator.rs:1312`), has **only test callers**: `tests/matrix_integration.rs:1923`, `scheduler_loop.rs` (`#[cfg(test)]`), and `task_orchestrator.rs` (`#[cfg(test)]`). Production never signs.

Net effect: the system fails **closed** (safe), but the headline feature is unusable end-to-end. The loop completes only in CI, where the live test harness (`signed_exec_task`, `tests/matrix_integration.rs:1906`) signs actions manually with the daemon key before `create_task`. Docs over-claim: `wiki/AI-Agent-Orchestration.md:5` says the loop "auto-claims assigned tasks … dispatches them" with no mention of the signing requirement; `docs/cli-reference.md:1665` calls exec actions "only local execution is supported at create time" but never states CLI-authored actions are unsigned and will always be blocked. `wiki/Home.md:19` is the only page that correctly says "assigned, **signed**, policy-allowed tasks".

We need a production authoring path: **the daemon signs `TaskActionAuthorization` on behalf of locally-authenticated IPC callers**, after the request crosses the local IPC boundary, mirroring the existing precedent in `task.cancel` (where the daemon already loads its own key and signs the linked invocation's cancel — `lifecycle.rs:611-633`).

## Goals

- A task created through the production `task.create` IPC path with a `Tool`/`Exec` action and **no** pre-signed authorization is signed daemon-side, then claimed, dispatched, and executed by the live scheduler — with **no** manual `sign_task_action` call anywhere in the user flow.
- `sign_task_action` (`task_orchestrator.rs:1312`) gains a production (non-`#[cfg(test)]`) caller.
- The daemon signs with **its own** persistent Ed25519 identity (`load_or_create_signing_key`, `signing.rs:156`), addressed (`target_agent`) to the agent that will execute, with a fresh nonce and a bounded `expires_at`.
- Signing is applied uniformly across both IPC verbs (`task.create` and action-/assignment-bearing `task.update`) by living in the shared session entry points `create_task_for_session` / `update_task_for_session`.
- The signed authorization survives publish and all later update round-trips: scheduler claim/finalize (`MatrixTaskStore`, `scheduler_loop.rs:104`) must not strip it; a `task.update` that changes the **action body** or **assignee** re-signs (because the signature binds `task_id` + action content + auth metadata, `task_orchestrator.rs:1306-1341`).
- The CLI stays unchanged (`authorization: None` at `cli.rs:3893`/`cli.rs:3911` is correct); a clear daemon-side error is surfaced to the CLI when signing cannot proceed.
- All existing blocked-unauthorized and replay tests stay green: actions signed by an untrusted key, addressed to the wrong agent, expired, or replayed remain blocked. Daemon-side signing at authoring time does **not** weaken executing-side enforcement.
- Docs corrected (`wiki/AI-Agent-Orchestration.md:5`, `docs/cli-reference.md` task-create section); `wiki/Home.md:19` remains accurate.

## Non-Goals

- **No change to the verifier side.** Target-agent binding (`task_orchestrator.rs:879-881`), trust-store key check, key resolution, signature verification (`task_orchestrator.rs:884-914`), and single-use nonce/expiry replay admission (`task_orchestrator.rs:933-963`) are complete and correct. Do not redo them.
- **No CLI signing.** The CLI must not gain the signing key, an authorization flag, or any credential surface. `authorization: None` from the CLI is correct.
- **No new IPC method or protocol event type.** Reuse `task.create` / `task.update` and the existing `com.mxagent.task.v1` `action.authorization` field.
- **No bypass of the approval gate or policy.** Authoring-side signing only attaches a *signature*; execution still requires local trust + deny-by-default policy + the approval gate (`scheduler_loop.rs:602-620`). A signature from an untrusted key stays blocked.
- **No auto-trust change.** Whether the executing agent trusts the authoring daemon's key is governed by the existing trust store (`trust publish`/`approve`). This issue does not auto-trust any key; the acceptance test's precondition ("daemon whose key is in the executing agent's trust store") is set up exactly as today.
- **No Windows support; no `unsafe`; MSRV stays 1.74.**
- Distinct exec exit codes, sandbox changes, and E2EE work are out of scope.

## Relevant Repository Context

**Crates.** `mx-agent-cli` (CLI surface), `mx-agent-daemon` (Matrix sync, crypto, policy, supervision, task orchestration), `mx-agent-protocol` (event/schema types incl. `TaskAction`, `TaskActionAuthorization`). Owning crate for this change is **`mx-agent-daemon`** (plus docs); `mx-agent-protocol` and `mx-agent-cli` are untouched in code.

**Architecture invariants (docs/architecture.md).**
- §1.2 / §10.3 trust split: Matrix device/E2EE identity ≠ mx-agent Ed25519 signing identity. *Room membership, device presence, and device verification never substitute for signing + trust + policy.* The `auth`/`trust` carve-out is the **only** exception to "CLI never touches credentials"; signing the daemon key is **not** part of that carve-out, so it must happen daemon-side.
- §9.2: "Task state is **advisory**. A task action only becomes executable when it carries a signed `authorization` from a locally trusted mx-agent signing key, addressed to the executing agent, within its expiry, and with a fresh nonce." The daemon verifies signature (binding task id + action) and trust *before* policy, and enforces replay/expiry *before* execution. The single-use nonce is "consumed only on the pass that actually proceeds to execute," so an approval-held task is not falsely rejected as a replay when it resumes.

**Authoring path (current).**
- IPC dispatch: `lifecycle.rs:573` (`task.create` → `create_task_for_session`), `lifecycle.rs:579` (`task.update` → `update_task_for_session`).
- `create_task_for_session` (`task.rs:457`) restores the client and calls `create_task`, which builds task state via `build_new_task` (`task.rs:227-255`, copies `options.action` verbatim at `task.rs:252`) and publishes.
- `update_task_for_session` (`task.rs:532`) → `update_task` (`task.rs:477`) → `update_task_in_room` (`task.rs:493`, reads current state) → `apply_and_publish_task` (`task.rs:512`) → `apply_update` (`task.rs:259`), which writes `action` **only when `options.action` is `Some`** (`task.rs:283-285`) — so an existing signed action round-trips untouched through state/title/result-only updates.

**Scheduler path (must stay signing-free).**
- `scheduler_pass_for_agent` (`scheduler_loop.rs:561`) builds the orchestrator with a trust store + replay cache and only claims tasks `assigned_to == agent.agent_id` (auto-claim disabled, `scheduler_loop.rs:622-624`).
- `MatrixTaskStore` (`scheduler_loop.rs:104`) wires `claim`/`finalize` to `crate::task::update_task_in_room`; its `UpdateTaskOptions` set `state`/`assigned_to`/`invocation_id`/`result` but **never `action`**, so the signed action is preserved automatically. **Signing must not be added to `update_task_in_room` / `apply_and_publish_task`**, or it would contaminate the scheduler's claim/finalize (which has no signing key and must not re-sign).

**Daemon signing key (existing).**
- `DaemonSigningKey` (`signing.rs:72`): `signing_key()` (`signing.rs:93`), `key_id()` (`signing.rs:107`), `verifying_key()`/`public_key_b64()`. Key file `0600` in the `0700` data dir (`signing.rs:145-173`).
- Precedent for daemon-side signing on behalf of an IPC caller: `task.cancel` loads `load_or_create_signing_key(&SessionPaths::resolve())` and signs (`lifecycle.rs:616-631`).

**Producer (existing, test-only callers).**
- `sign_task_action(signing_key, key_id, task_id, action, requesting_agent, target_agent, created_at, expires_at, nonce) -> Result<TaskActionAuthorization, SignatureError>` (`task_orchestrator.rs:1312`). Signs the canonical bytes binding `task_id`, `action.without_authorization()`, and the auth metadata. It is already `pub`.
- `TaskAction::authorization()` (`schema.rs:650`) and `TaskAction::without_authorization()` (`schema.rs:661`) exist.

**Helpers for nonce/timestamps (existing, crate-internal).**
- Nonce: `mx_agent_protocol::id::generate_request_id()` (`id.rs:104`) — used as the nonce in the signed exec/call dispatch path (`call.rs:141`).
- Timestamps: `crate::exec_ipc::rfc3339_after(Duration)` (`exec_ipc.rs:547`); `rfc3339_after(Duration::ZERO)` yields "now", `rfc3339_after(ttl)` yields the expiry. Used at `exec_ipc.rs:456-457`, `call.rs:143`.

## Proposed Implementation

### Overview

Introduce a single daemon-internal helper that, given the daemon signing key, the task id, the action, the requester, and the **effective executing agent**, returns the action with a freshly signed `TaskActionAuthorization` attached. Call it from `create_task_for_session` and `update_task_for_session` — the two IPC entry points — so signing happens after the request crosses the local IPC boundary and *before* the action is published. Never call it from the scheduler/store update path.

### 1. Signing helper (`crates/mx-agent-daemon/src/task.rs`)

Add a private helper (document it as a daemon-internal function; it does not need to be `pub`):

```rust
/// Bounded validity window for a daemon-authored task-action authorization.
/// Long enough to cover dependency waits and a pending approval, but bounded so a
/// captured-but-never-executed authorization does not stay valid forever. The
/// single-use nonce (burned on execution) already prevents replay within this
/// window. Overridable via `MX_AGENT_TASK_AUTH_TTL` (seconds); see Open Questions.
const TASK_AUTH_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Attach a daemon-authored signature to an actionable, unsigned task action.
///
/// Returns `Some(signed_action)` when the daemon signed the action on behalf of a
/// locally-authenticated IPC caller, or `None` to leave the caller's action field
/// untouched (no action, action already carries an authorization, or no executing
/// agent to address). Signs with the daemon's own Ed25519 identity, addressed to
/// `target_agent` (the executing agent), with a fresh nonce and bounded expiry.
fn authored_authorization(
    signing: &DaemonSigningKey,
    task_id: &str,
    action: &TaskAction,
    requesting_agent: &str, // task creator (bound into the signature; advisory at the verifier)
    target_agent: &str,     // effective assignee = the executing agent
) -> Result<Option<TaskAction>, SignatureError>
```

Behavior:
- Return `Ok(None)` if `action.authorization().is_some()` — a pre-signed action (e.g. a test or a future programmatic caller) is left exactly as supplied. **This is the compatibility hinge** that keeps `signed_exec_task` and all manually-signed tests green.
- Return `Ok(None)` if `target_agent` is empty — an unassigned actionable task cannot be addressed yet; leave it advisory (it will be signed at assignment time; see §3 update rules).
- Otherwise build the unsigned action via `action.without_authorization()`, call `sign_task_action(signing.signing_key(), signing.key_id(), task_id, &unsigned, requesting_agent, target_agent, rfc3339_after(Duration::ZERO), rfc3339_after(task_auth_ttl()), generate_request_id())`, then return `Ok(Some(action_with_authorization))`.
- Reconstruct the action variant with `authorization: Some(auth)` (match on `TaskAction::Tool`/`TaskAction::Exec`, mirroring the test in `matrix_integration.rs:1935-1952` — or add a small `TaskAction::with_authorization(auth)` helper in `mx-agent-protocol` to avoid the match, symmetric to the existing `without_authorization`). Prefer the protocol helper for readability and reuse; document it.

Add a `task_auth_ttl()` that reads `MX_AGENT_TASK_AUTH_TTL` (seconds, parsed; falls back to `TASK_AUTH_TTL` on unset/invalid).

### 2. Sign on create (`create_task_for_session`, `task.rs:457`)

```rust
pub async fn create_task_for_session(
    session: &StoredSession,
    options: &CreateTaskOptions,
) -> Result<TaskState, WorkspaceError> {
    let client = restore_client(session).await?;
    let mut options = options.clone();
    if let Some(action) = &options.action {
        let signing = load_or_create_signing_key(&SessionPaths::resolve())
            .map_err(|e| WorkspaceError::Io(io::Error::other(e.to_string())))?;
        let requester = options.created_by.clone().unwrap_or_default(); // see Risks: resolve vs. client.user_id()
        let task_id_preview = options.task_id.clone().unwrap_or_default(); // see Risks: id generation timing
        if let Some(signed) =
            authored_authorization(&signing, &task_id_preview, action, &requester, &options.assigned_to)
                .map_err(/* -> WorkspaceError */)?
        {
            options.action = Some(signed);
        }
    }
    create_task(&client, &options).await
}
```

**Critical: `task_id` must be known before signing**, because the signature binds `task_id`. Today `create_task` (`task.rs:436-453`) generates the id when `options.task_id` is `None`. The signing helper needs the *final* id. Recommended approach: lift id generation so the resolved id is available before signing — e.g. resolve `task_id` in `create_task_for_session` (generate when absent) and pass the concrete id through, or refactor `create_task` to expose an "already-resolved-id" inner that both the wrapper and signing use. **Do not sign against a placeholder id**; a mismatch makes the verifier reject with `invalid_signature`. This is the single most important correctness detail on the create path — call it out in the implementation and cover it with a test (a `task create` with an auto-generated id must still execute).

Only sign when `options.assigned_to` is non-empty (handled inside `authored_authorization`); an unassigned actionable task is left advisory.

### 3. Sign / re-sign on update (`update_task_for_session`, `task.rs:532`)

The update path must (re)sign in exactly these cases, and leave the action untouched otherwise:

| Update shape | Action handling |
|---|---|
| Sets a new action (`options.action = Some`, `authorization: None`) | Sign the new action, addressed to the **effective** assignee. |
| Sets a new action that already carries an authorization | Leave as supplied (pre-signed). |
| Changes assignee (`options.assigned_to = Some`) on a task that already has an actionable action | **Re-sign** the existing action addressed to the new assignee (covers the "unassigned at create → assigned later" case and re-targets a moved task). |
| State / title / description / result / invocation only | Do **not** touch the action; the existing signature round-trips via `apply_update` (`task.rs:283-285`). |

Because resolving the *effective* action (when reassigning without a new action) and the *effective* assignee (when setting an action without reassigning) requires the current task, the cleanest implementation reads current state once and signs with full knowledge. Recommended: add a daemon-internal `update_task_for_session` flow that:

1. `let mut options = options.clone();`
2. loads the signing key (only if the update could affect signing: `options.action.is_some() || options.assigned_to.is_some()`),
3. restores the client and reads the current `TaskState` (reuse `update_task`'s `sync_and_get_room` + `read_task_state`; consider threading an optional signer into a new internal `update_task_with_signing(client, options, Some(&signing))` so the read is not duplicated — `update_task(client, options)` stays the no-signer variant the scheduler-adjacent code paths use),
4. computes `effective_action = options.action.as_ref().or(current.action.as_ref())` and `effective_assignee = options.assigned_to.as_deref().unwrap_or(&current.assigned_to)`,
5. if `effective_action` is actionable and `(authored_authorization(...))` returns `Some`, set `options.action = Some(signed)` (this both signs a brand-new action and re-targets an existing one because `without_authorization()` strips the stale auth before re-signing),
6. delegates to the existing apply/publish (`apply_and_publish_task`), which already enforces the `expected_state_rev` stale guard and transition validation.

**Keep signing out of `update_task_in_room` and `apply_and_publish_task`** (the scheduler entry points) so claim/finalize never attempt to sign.

### 4. IPC dispatch (`lifecycle.rs:573-584`)

No change to the dispatch table. The session functions now sign internally, exactly like `task.cancel` already loads the key internally. A signing failure becomes a `WorkspaceError` and is surfaced to the CLI as a JSON-RPC error (mirror `task.cancel`'s `WorkspaceError::Io(io::Error::other(...))` mapping at `lifecycle.rs:616-617`).

### 5. CLI (`crates/mx-agent-cli/src/cli.rs`)

No code change. `build_task_action` keeps emitting `authorization: None` (`cli.rs:3893`, `cli.rs:3911`). The CLI surfaces whatever JSON-RPC error the daemon returns when signing fails (existing error rendering).

## Affected Files / Crates / Modules

**Modify (code):**
- `crates/mx-agent-daemon/src/task.rs` — add `authored_authorization` + `task_auth_ttl` + `TASK_AUTH_TTL`; sign in `create_task_for_session` (and resolve `task_id` before signing); sign/re-sign in `update_task_for_session` (new internal `update_task_with_signing` or equivalent). Needs `use` of `crate::signing::{load_or_create_signing_key, DaemonSigningKey}`, `crate::session::SessionPaths`, `crate::task_orchestrator::sign_task_action`, `crate::exec_ipc::rfc3339_after`, `mx_agent_protocol::id::generate_request_id`, `std::time::Duration`, `std::io`.
- `crates/mx-agent-protocol/src/schema.rs` — *(optional, recommended)* add `TaskAction::with_authorization(self, auth) -> Self` symmetric to `without_authorization`; document it. No schema/wire change.

**Read / reference (no change expected):**
- `crates/mx-agent-daemon/src/lifecycle.rs:573-584, 611-633` — dispatch + `task.cancel` signing precedent.
- `crates/mx-agent-daemon/src/task_orchestrator.rs:845-963, 1294-1341` — verifier + `sign_task_action`.
- `crates/mx-agent-daemon/src/scheduler_loop.rs:104-140, 532-624` — `MatrixTaskStore`, orchestrator wiring (confirm `action` not stripped).
- `crates/mx-agent-daemon/src/signing.rs:72-173` — `DaemonSigningKey`.
- `crates/mx-agent-cli/src/cli.rs:3838-3916` — CLI action builder (unchanged).

**Tests / docs:** `crates/mx-agent-daemon/tests/matrix_integration.rs`; unit tests in `task.rs`; `wiki/AI-Agent-Orchestration.md`; `docs/cli-reference.md`; (verify, do not regress) `wiki/Home.md`.

## CLI / API Changes

**None to the public surface.** No new flags, no new IPC method, no new options field. `task.create`/`task.update` keep their `CreateTaskOptions`/`UpdateTaskOptions` params. The observable behavior change is: a `Tool`/`Exec` action submitted with `authorization: None` is returned (in the resulting `TaskState`) carrying a daemon-signed `authorization`. The new daemon-side failure mode (signing key unavailable) surfaces as an existing-shape JSON-RPC error to the CLI.

## Data Model / Protocol Changes

**None to the wire schema.** `com.mxagent.task.v1` already carries `action.authorization` (`TaskActionAuthorization`, `schema.rs:580`); this change merely **populates** it on the production path instead of leaving it `null`. The field is additive and `skip_serializing_if = "Option::is_none"`, so older tasks remain valid and unaffected. The optional `TaskAction::with_authorization` helper is a pure in-crate API addition, not a serialization change. New env var `MX_AGENT_TASK_AUTH_TTL` (seconds) is additive and optional.

## Security Considerations

- **CLI never holds credentials.** Signing happens strictly daemon-side, after the local IPC boundary (peer-UID-gated, `0600` socket). The CLI never receives the signing key, the private key bytes, or an authorization flag. This stays within the architecture §10.3 model; the daemon-signing precedent already exists for `task.cancel`.
- **Authoring-side signing does not weaken executing-side enforcement.** The executing agent still runs the *full* gate at dispatch: Ed25519 signature verify + local trust store (final authority; revoked keys rejected) + deny-by-default policy + approval gate + replay/expiry. A daemon signs with **its own** key; for a *different* executing daemon to run the action, that daemon's trust store must already trust the authoring key (`trust publish`/`approve`). **Room membership is not execution permission** — this change adds a signature, not a grant. Untrusted/wrong-target/expired/replayed authorizations stay blocked (`task_orchestrator.rs:874-914, 933-963`).
- **Approval gate is not bypassed.** Approval-gated actions still need an authenticated, unexpired decision before running (`scheduler_loop.rs:602-620`). The nonce is burned only on the executing pass, so a held-then-approved task is not falsely replay-rejected (`task_orchestrator.rs:920-932`). Authoring-side signing changes none of this.
- **Bounded replay window.** Each authorization carries a fresh single-use nonce and a bounded `expires_at`. The nonce (burned on execution) prevents replay even inside the window; the TTL bounds how long a captured-but-unexecuted authorization stays valid. The default must be generous enough to survive dependency waits + a pending approval (see Open Questions on TTL).
- **No secrets in logs or output.** The private key is never logged and never leaves the daemon; `sign_task_action` only uses it internally. The *public* authorization material (key id, nonce, signature bytes, timestamps, target/requesting agent) is **non-secret** and may legitimately appear in `task` JSON output and non-sensitive logs — no redaction needed, but log only non-sensitive metadata (task id, action kind, target) at info, never raw args/command. Key file stays `0600` (`signing.rs:150-173`).
- **Signature binding integrity.** The signature binds `task_id` + `action.without_authorization()` + auth metadata. Two correctness traps: (1) sign against the **final** `task_id` (resolve auto-generated ids *before* signing); (2) **re-sign** whenever an update changes the action body or assignee, otherwise the published action and its signature diverge and the verifier rejects it (`invalid_signature` / `wrong_target`).
- **Unix-only, no `unsafe`, MSRV 1.74.** No new platform assumptions; all helpers reuse existing portable code.

## Testing Plan

**Unit tests (daemon, `task.rs` `#[cfg(test)]`) — pure helper, no live Matrix:**
- `authored_authorization` signs an actionable, unsigned, assigned action and the result verifies via `verify_task_action_signature` against the daemon verifying key, with `target_agent == assigned_to`, a non-empty nonce, and `expires_at` within the TTL.
- `authored_authorization` returns `None` (leaves untouched) when: action already carries an authorization; `assigned_to` is empty; action is `None`.
- Round-trip: an action signed for `task_id = T` fails verification when bound to a different id (guards the auto-id-resolution trap).
- TTL override: `MX_AGENT_TASK_AUTH_TTL` parses; invalid/unset falls back to default.
- *(if added)* `TaskAction::with_authorization` round-trips with `without_authorization`.

**Unit / integration tests for the session wrappers** (may need a thin fake or to exercise the helper directly if a live client is required — prefer factoring the signing decision into a pure function so it is testable without Matrix):
- Create signs an unsigned assigned action; create leaves an unassigned action unsigned; create leaves a pre-signed action untouched.
- Update signs a newly-supplied action; update re-signs on reassignment of an existing actionable task; update with state/title/result only does not alter the action (existing signature round-trips); update leaves a pre-signed supplied action untouched.

**Orchestrator regression (must stay green, `task_orchestrator.rs`):**
- `unsigned_action_does_not_execute_when_trust_required` (`:2937`), `untrusted_key_signed_action_does_not_execute` (`:2963`), `expired_signed_action_does_not_execute` (`:3033`), `replayed_signed_action_does_not_execute_twice` (`:3055`), `approval_held_task_is_not_replay_blocked_when_it_resumes` (`:3095`), and `wrong_target`/`unresolved_key` cases. These exercise the verifier and are unaffected — confirm no regression.

**Live E2E (Tuwunel, `crates/mx-agent-daemon/tests/matrix_integration.rs`, `matrix-integration` CI job):**
- New test: a task created through the **production `task.create` path** (i.e. `create_task_for_session`, or whatever production helper now signs) with an `Exec` action and **no** pre-signed authorization is claimed, dispatched, and executed by the live scheduler — daemon's key in the executing agent's trust store, deny-by-default policy permitting the exec. Assert it reaches `succeeded` with the expected result, and assert no manual `sign_task_action` appears in the user flow.
- Contrast/retain `signed_exec_task` (`matrix_integration.rs:1906`) as the manually-signed control to prove both paths coexist (pre-signed action is honored unchanged).
- *(recommended)* A negative live case: a task whose action is daemon-signed but addressed to / signed by a key the executing agent does **not** trust stays blocked (`untrusted_key`/`wrong_target`), proving authoring-side signing did not weaken execution.

**Gates:** `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo build --all`, `cargo test --all` all green.

## Documentation Updates

- **`wiki/AI-Agent-Orchestration.md:5`** (status banner) — state that the live scheduler runs assigned, **signed**, policy-allowed tasks, and that **the daemon signs CLI-authored task actions on behalf of the local IPC caller** (addressed to the executing agent), so the CLI never holds the signing key. Remove the implication that any "assigned" task runs.
- **`docs/cli-reference.md`** (the `task create` Behavior section near the current `:1665` "only local execution is supported at create time") — explain that `--tool`/`--exec` actions are submitted unsigned and the **daemon signs them with its own Ed25519 identity**, addressed to the assigned agent; that an **unassigned** actionable task is left advisory until assigned (then signed on the assigning update); that execution still requires the executing agent to trust the daemon's key under deny-by-default policy (membership ≠ execution); and what error appears if signing cannot proceed. Document `MX_AGENT_TASK_AUTH_TTL` if added.
- **`wiki/Home.md:19`** — already correct ("assigned, **signed**, policy-allowed tasks"); verify it still reads accurately after the banner edit; no change expected.
- **`README.md` Project status table** (`README.md:48-49`) — verify the "Live daemon scheduler loop" row still reads accurately; optionally add "(actions authored via the CLI are daemon-signed)" so the table no longer implies a signing gap. Keep alpha tags honest.
- Document the new public `TaskAction::with_authorization` (if added) and the `authored_authorization` daemon helper with `///` doc comments (`missing_docs` is `-D warnings` in CI).

## Risks and Open Questions

1. **TTL value (decision needed).** A task may legitimately sit `pending`/`assigned` for a long time (waiting on a dependency or a human approval) before it executes; `expires_at` must outlast that or the authorization expires before its first valid execution. The signed exec/call path uses ~300 s, which is far too short here. **Recommendation:** default 24 h, overridable via `MX_AGENT_TASK_AUTH_TTL`; the single-use nonce already bounds replay within the window. Confirm the default and whether it should be config-file-driven rather than env-driven.
2. **`task_id` resolution before signing (must-fix).** Auto-generated ids are minted inside `create_task`; signing must use the *final* id. Refactor so the id is resolved before `authored_authorization` runs. A regression here yields silent `invalid_signature` blocks. Covered by a dedicated test.
3. **`requesting_agent` value.** The verifier does not semantically enforce `requesting_agent` (only `target_agent` + trust + signature), but it is bound into the signature. Use the resolved `created_by` (which `create_task` defaults to the client's user id when empty — resolve it before signing for consistency, or accept a possibly-empty requester). Decide whether to thread the resolved `created_by` into signing or sign with the daemon's agent id; document the choice.
4. **Extra read on the update path.** Re-signing on reassignment-without-new-action needs the current task. Prefer threading an optional signer into a single read (`update_task_with_signing`) over a second `sync_and_get_room`. If a duplicate read is unavoidable, note that the `expected_state_rev` guard still protects against lost updates, though a race could bind a stale action body (rare; the publish would then be stale-rejected when `expected_state_rev` is supplied).
5. **Self-trust precondition.** For the common single-daemon (author == executor) case, the daemon's own key must be in its own trust store for the scheduler to admit it. This is a trust-setup precondition (as in the live harness), not something this issue changes — but the docs/test must make the precondition explicit so users don't see `untrusted_key` and think the feature is broken.
6. **Pre-signed-action compatibility.** The "sign only when `authorization.is_none()`" rule is what keeps `signed_exec_task` and other manually-signed tests valid. Verify no production caller ever submits a partially/incorrectly pre-signed action expecting the daemon to fix it (none today).
7. **Approval-gated + long TTL interaction.** A long TTL plus a never-answered approval means the authorization is admissible until the approval request's own `expires_at` finalizes the task `blocked` (`approval_expired`). Confirm the two expiries compose as intended (approval expiry should bound the wait independently of the action TTL).

## Implementation Checklist

1. *(optional, recommended)* Add `TaskAction::with_authorization(self, TaskActionAuthorization) -> Self` to `crates/mx-agent-protocol/src/schema.rs`, symmetric to `without_authorization`; document it; add a round-trip unit test.
2. In `crates/mx-agent-daemon/src/task.rs`: add `TASK_AUTH_TTL`, `task_auth_ttl()` (reads `MX_AGENT_TASK_AUTH_TTL`), and the `authored_authorization(...)` helper using `sign_task_action`, `rfc3339_after`, and `generate_request_id`. Only signs actionable, unsigned, assigned actions; returns `Ok(None)` otherwise. Document all of it.
3. Refactor `create_task` / `create_task_for_session` so the **final `task_id` is resolved before signing**; sign `options.action` in `create_task_for_session` against the resolved id, addressed to `options.assigned_to`, requester = resolved `created_by`. Load the key via `load_or_create_signing_key(&SessionPaths::resolve())`; map errors to `WorkspaceError::Io(io::Error::other(...))`.
4. Add `update_task_with_signing` (or equivalent) used by `update_task_for_session`: read current state once, compute effective action + assignee, (re)sign per the §3 rules, then delegate to the existing apply/publish. Keep `update_task_in_room` / `apply_and_publish_task` signing-free so the scheduler/`MatrixTaskStore` path is unchanged.
5. Confirm `MatrixTaskStore::claim`/`finalize` and `apply_update` never overwrite `action` during scheduler updates (they don't today — verify with a test that claims/finalizes a signed task and re-reads the preserved authorization).
6. Leave the CLI unchanged; verify `task create`/`task update` still emit `authorization: None`.
7. Unit tests per the Testing Plan (helper behavior, create/update signing rules, task-id binding, TTL).
8. New live E2E in `matrix_integration.rs`: production `task.create` exec action with no pre-signed authorization → claimed/dispatched/executed; retain `signed_exec_task` as the pre-signed control; add the untrusted-key negative case.
9. Run the existing orchestrator block-unauthorized/replay tests; confirm green.
10. Update docs: `wiki/AI-Agent-Orchestration.md:5`, `docs/cli-reference.md` task-create section, verify `wiki/Home.md:19` and `README.md` status rows; document `MX_AGENT_TASK_AUTH_TTL` if added.
11. Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo build --all`, `cargo test --all`; ensure the `matrix-integration` job is green.
```
