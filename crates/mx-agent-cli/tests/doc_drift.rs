//! Drift guards for documentation files corrected in issues #271 and #269.
//!
//! Each test asserts that:
//!   - the stale pre-v0.2.0 phrase is absent, and
//!   - the correct post-fix phrase is present.
//!
//! Files are embedded at compile time via `include_str!` so failures point
//! directly at committed source, not a runtime filesystem path.

const README: &str = include_str!("../../../README.md");
const ROADMAP: &str = include_str!("../../../docs/roadmap-rust.md");
const USER_GUIDE: &str = include_str!("../../../docs/user-guide.md");
const ALPHA_CHECKLIST: &str = include_str!("../../../docs/alpha-release-checklist.md");
const ARCHITECTURE: &str = include_str!("../../../docs/architecture.md");
const SECURITY_HARDENING: &str = include_str!("../../../docs/security-hardening.md");
const IPC_MOD: &str = include_str!("../../mx-agent-daemon/src/ipc.rs");

/// Phase 10 of the roadmap must describe the live scheduler loop and the
/// signed Matrix `exec` transport as *delivered*, not as remaining work.
///
/// Stale text (issue #271): "Remaining work: wiring that engine into a live
/// `/sync` scheduler loop … plus the signed Matrix transport for remote `exec`
/// (tracked by #155)."
#[test]
fn roadmap_phase10_scheduler_and_matrix_exec_delivered() {
    assert!(
        !ROADMAP.contains("Remaining work: wiring that engine"),
        "roadmap Phase 10 must not list the scheduler loop as remaining work"
    );
    assert!(
        !ROADMAP.contains("tracked by #155"),
        "roadmap must not frame issue #155 as open remaining work"
    );
    // Positive: the delivered state cites all closed issues.
    assert!(
        ROADMAP.contains("all closed"),
        "roadmap Phase 10 must note that the tracking issues are all closed"
    );
    // Positive: the live scheduler-loop entry point is mentioned as delivered.
    assert!(
        ROADMAP.contains("run_scheduler_loop"),
        "roadmap must reference run_scheduler_loop as a delivered feature"
    );
}

/// The two-agent demo in the user guide must show the current 6-column
/// `agent list` format with status `active`, not the stale 4-column format
/// with status `online`.
///
/// Stale text (issue #271): `alice-agent generic online shell,test`
/// Current text: `alice-agent  generic  active  active  8s ago  shell,test`
#[test]
fn user_guide_agent_list_demo_six_columns_active_status() {
    // Negative: the stale 4-column `generic  online` pattern must be gone.
    assert!(
        !USER_GUIDE.contains("generic  online"),
        "user-guide demo must not show the stale 4-column 'online' agent list format"
    );
    // Positive: both status and liveness columns carry 'active'.
    // The 6-column renderer emits: kind=generic, status=active, liveness=active.
    assert!(
        USER_GUIDE.contains("generic  active"),
        "user-guide demo must show kind 'generic' and status 'active'"
    );
    assert!(
        USER_GUIDE.contains("active   active"),
        "user-guide demo must include both status and liveness columns (both 'active')"
    );
    // Positive: the demo still shows alice-agent and capabilities.
    assert!(
        USER_GUIDE.contains("alice-agent") && USER_GUIDE.contains("shell,test"),
        "user-guide demo must include alice-agent with shell,test capabilities"
    );
}

/// Production E2EE hardening must be marked as shipped in the alpha-release
/// checklist, not listed as "still landing".
///
/// Stale state (issue #271): a bullet listed device verification UX,
/// cross-signing, and key backup as "still landing".  The fix moves E2EE
/// hardening into the already-shipped narrative.
#[test]
fn alpha_checklist_e2ee_hardening_is_shipped_not_pending() {
    // Positive: the shipped state is explicitly stated.
    assert!(
        ALPHA_CHECKLIST.contains("production E2EE hardening shipped"),
        "alpha checklist must confirm that production E2EE hardening shipped"
    );
    // Positive: cross-reference both tracking issues.
    assert!(
        ALPHA_CHECKLIST.contains("#240") && ALPHA_CHECKLIST.contains("#256"),
        "alpha checklist must cross-reference E2EE hardening issues #240 and #256"
    );
    // Negative: "production E2EE hardening" must not be the subject of
    // "still landing".  Extract the 100-char window immediately preceding the
    // phrase to check the local sentence context.  "Very-large-output tuning
    // is still landing" is ~300 chars earlier in the same bullet so it does
    // not appear in this window.
    let idx = ALPHA_CHECKLIST
        .find("production E2EE hardening")
        .expect("alpha checklist must mention production E2EE hardening");
    let lookback = &ALPHA_CHECKLIST[idx.saturating_sub(100)..idx];
    assert!(
        !lookback.contains("still landing"),
        "the sentence leading up to 'production E2EE hardening' must not say \
         'still landing'; got lookback: {lookback}"
    );
}

/// Architecture §11.3 must describe daemon restart recovery as room-state
/// reconciliation against `com.mxagent.task.v1` and
/// `com.mxagent.invocation.v1`, not as OS process-table reconciliation.
///
/// Stale text (issue #271):
///   step 2: "Load active invocations from local store"
///   step 4: "Reconcile local process table with invocation state."
#[test]
fn architecture_recovery_is_room_state_not_process_table() {
    // Negative: the stale step-2 wording must be gone.
    assert!(
        !ARCHITECTURE.contains("Load active invocations from local store"),
        "architecture §11.3 must not describe loading invocations from a local store"
    );
    // Negative: the stale step-4 wording must be gone.
    assert!(
        !ARCHITECTURE.contains("Reconcile local process table"),
        "architecture §11.3 must not describe reconciling a local process table"
    );
    // Positive: step 2 now references the Matrix room-state event type.
    assert!(
        ARCHITECTURE.contains("com.mxagent.task.v1"),
        "architecture §11.3 must reference com.mxagent.task.v1 room state for recovery"
    );
    // Positive: step 4 references the invocation snapshot event type.
    assert!(
        ARCHITECTURE.contains("com.mxagent.invocation.v1"),
        "architecture §11.3 must reference com.mxagent.invocation.v1 for reconciliation"
    );
    // Positive: the clarification that no process table is used must be explicit.
    assert!(
        ARCHITECTURE.contains("no OS process table is consulted"),
        "architecture §11.3 must explicitly state that no OS process table is consulted"
    );
}

// ── Issue #269: auth login / trust bypass daemon IPC — doc drift guards ────────
//
// The four docs below previously claimed that all Matrix-backed commands are
// fully daemon-IPC-mediated and that "the CLI never builds a Matrix client".
// The fix (issue #269) corrected them to name the auth/trust carve-out
// explicitly.  These tests prevent regression back to the stale phrasing.

/// README project-status table must name `auth login` as a CLI-initiated,
/// same-binary exception — not as a fully daemon-IPC-mediated command.
///
/// Stale state (issue #269): the table row implied all listed commands were
/// daemon-IPC-mediated; the auth/trust exception was absent.
#[test]
fn readme_project_status_names_auth_login_as_cli_initiated_exception() {
    // Positive: the auth/trust carve-out must be explicitly named.
    assert!(
        README.contains("CLI-initiated"),
        "README must describe auth login as a CLI-initiated exception, not daemon-IPC-mediated"
    );
    // Positive: the security rationale (same binary, same UID) must be present.
    assert!(
        README.contains("same binary") || README.contains("same-binary"),
        "README must explain that auth login is safe because CLI and daemon are the same binary"
    );
}

/// README description section must call out the advisory lock that serialises
/// concurrent `auth login` / daemon writes — the fix for the concurrency hazard
/// in issue #269.
#[test]
fn readme_advisory_lock_documented_for_auth_login_concurrency() {
    assert!(
        README.contains("advisory file lock") || README.contains("advisory lock"),
        "README must document the advisory file lock that serializes auth login vs daemon \
         session/key writes (issue #269)"
    );
}

/// User guide must name `auth login` as a deliberate CLI-initiated exception
/// to daemon-IPC mediation, matching the accepted carve-out in architecture §10.3.
///
/// Stale state (issue #269): lines 7-11 implied the CLI never builds a Matrix
/// client for any command, with no exception stated.
#[test]
fn user_guide_auth_login_named_as_deliberate_exception() {
    // Positive: the deliberate exception must be stated.
    assert!(
        USER_GUIDE.contains("deliberate") || USER_GUIDE.contains("carve-out"),
        "user-guide must describe auth login as a deliberate or carve-out exception"
    );
    // Positive: architecture §10.3 cross-reference lets readers verify the rationale.
    assert!(
        USER_GUIDE.contains("architecture")
            && (USER_GUIDE.contains("10.3") || USER_GUIDE.contains("§10.3")),
        "user-guide must cross-reference architecture §10.3 for the auth/trust carve-out"
    );
}

/// Security-hardening token-isolation model must document the auth/trust
/// carve-out **and** the advisory flock that guards concurrent writes.
///
/// Stale state (issue #269): line 63 said "the CLI never builds a Matrix
/// client" as an unqualified universal claim.
#[test]
fn security_hardening_auth_trust_carve_out_with_advisory_lock() {
    // Positive: the carve-out must be named explicitly.
    assert!(
        SECURITY_HARDENING.contains("carve-out"),
        "security-hardening must name the auth/trust carve-out exception"
    );
    // Positive: the advisory lock must be mentioned as the concurrency fix.
    assert!(
        SECURITY_HARDENING.contains("flock") || SECURITY_HARDENING.contains("advisory"),
        "security-hardening must document the advisory lock serializing auth login writes \
         (issue #269)"
    );
    // Positive: the accepted-exception rationale must appear.
    assert!(
        SECURITY_HARDENING.contains("accepted")
            || SECURITY_HARDENING.contains("same-binary")
            || SECURITY_HARDENING.contains("same UID"),
        "security-hardening must explain why the auth/trust carve-out is safe (same UID)"
    );
}

/// Architecture §10.3 must document the advisory `flock` on `.write.lock` and
/// cite issue #269 — these were added as part of the concurrency-hazard fix.
#[test]
fn architecture_advisory_lock_and_issue_269_documented() {
    // Positive: the advisory lock file name must appear in the IPC-protocol section.
    assert!(
        ARCHITECTURE.contains(".write.lock"),
        "architecture §10.3 must name the advisory lock file (.write.lock)"
    );
    // Positive: issue #269 must be cited as the reason for the lock.
    assert!(
        ARCHITECTURE.contains("#269"),
        "architecture must cite issue #269 as the motivation for the advisory write lock"
    );
    // Negative: auth.login must NOT appear as a daemon-IPC method in the table,
    // because auth login is CLI-local (the carve-out).
    assert!(
        !ARCHITECTURE.contains("| `auth.login`") && !ARCHITECTURE.contains("auth.login |"),
        "architecture IPC dispatch table must not list auth.login (it is CLI-local, not daemon-mediated)"
    );
}

// ── Issue #307: loopback exec/PTY policy confinement floor — doc drift guards ──
//
// Before #307, loopback `exec`/`--pty` ran with no sandbox/timeout/output cap and
// the docs claimed local exec followed the same verify→policy→runner pipeline as a
// remote one. The fix applies the operator's execution confinement floor to the
// loopback path and corrects the docs. These guard against regressing to the
// stale, over-claiming wording.

/// README must no longer claim a local exec follows the *same path* (full
/// verify→policy→runner pipeline) as a remote one — that was false for loopback.
/// It must instead describe the loopback **confinement floor**.
#[test]
fn readme_loopback_exec_describes_confinement_floor_not_same_path() {
    // Negative: the stale over-claim must be gone.
    assert!(
        !README.contains("follows the **same path** as a remote one"),
        "README must not claim a local exec follows the same verify→policy→runner \
         pipeline as a remote one (false for the loopback path; issue #307)"
    );
    // Positive: the corrected description names the confinement floor.
    assert!(
        README.contains("confinement floor"),
        "README must describe the loopback exec confinement floor (issue #307)"
    );
}

/// security-hardening must no longer assert the PTY path skips the sandbox
/// backend, and must document the loopback confinement floor + the remote-only
/// scope of the engine's deny-by-default gate.
#[test]
fn security_hardening_loopback_floor_and_pty_sandbox_corrected() {
    // Negative: the stale "PTY does not route through the sandbox backend" claim
    // must be gone (both batch and PTY route through the backend now).
    assert!(
        !SECURITY_HARDENING.contains("PTY exec path does not route through the sandbox backend"),
        "security-hardening must not claim the PTY exec path skips the sandbox backend (issue #307)"
    );
    // Positive: the loopback confinement floor must be documented.
    assert!(
        SECURITY_HARDENING.contains("confinement floor"),
        "security-hardening must document the loopback execution confinement floor (issue #307)"
    );
    // Positive: the deny-by-default engine fact must be scoped to *remote* exec/call.
    assert!(
        SECURITY_HARDENING.contains("*remote* `exec` and `call`"),
        "security-hardening must scope the deny-by-default engine claim to remote exec/call (issue #307)"
    );
}

// ── Issue #310: sandbox backends fail-closed + hardening — doc drift guards ───
//
// Before #310, firejail/chroot were "Selectable in policy where available" (but
// silently ran unsandboxed) and the docs said the PTY path skipped the sandbox
// backend. The fix rejects firejail/chroot at load and routes the PTY through the
// backend. These guard the corrected wording.

/// security-hardening must mark firejail/chroot as not implemented / rejected,
/// not as "selectable where available".
#[test]
fn security_hardening_firejail_chroot_rejected_not_selectable() {
    // Negative: the stale "selectable where available" wording must be gone.
    assert!(
        !SECURITY_HARDENING.contains("Selectable in policy where available"),
        "security-hardening must not claim firejail/chroot are selectable (issue #310)"
    );
    // Positive: they are documented as not implemented / rejected at load.
    assert!(
        SECURITY_HARDENING.contains("rejected at policy load")
            || SECURITY_HARDENING.contains("Not implemented"),
        "security-hardening must state firejail/chroot are rejected at policy load (issue #310)"
    );
    // Positive: the container image policy key is documented.
    assert!(
        SECURITY_HARDENING.contains("container_image"),
        "security-hardening must document the execution.container_image policy key (issue #310)"
    );
}

/// security-hardening must no longer claim the PTY path skips the sandbox backend
/// in the filesystem-confinement section.
#[test]
fn security_hardening_pty_routes_through_sandbox_backend() {
    assert!(
        !SECURITY_HARDENING.contains("does not route through the sandbox backend"),
        "security-hardening must not claim the PTY path skips the sandbox backend (issue #310)"
    );
}

/// The `ipc.rs` module doc must name the `auth`/`trust` carve-out so a reader
/// of that file cannot conclude that ALL commands are daemon-IPC-mediated.
///
/// Stale state (issue #269): lines 1-11 said "the stateless CLI does not
/// restore Matrix sessions or build Matrix clients itself" with no exception.
#[test]
fn ipc_module_doc_names_auth_trust_exception() {
    // Positive: the carve-out keyword must appear.
    assert!(
        IPC_MOD.contains("carve-out"),
        "ipc.rs module doc must name the auth/trust carve-out exception"
    );
    // Negative: no AuthLoginParams or auth_login IPC param struct should be defined,
    // since auth login is CLI-local and has no IPC method.
    assert!(
        !IPC_MOD.contains("AuthLoginParams"),
        "ipc.rs must not define AuthLoginParams (auth login is CLI-local, not daemon-IPC-mediated)"
    );
}
