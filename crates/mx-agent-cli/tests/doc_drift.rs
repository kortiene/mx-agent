//! Drift guards for the four documentation files corrected in issue #271.
//!
//! Each test asserts that:
//!   - the stale pre-v0.2.0 phrase is absent, and
//!   - the correct post-fix phrase is present.
//!
//! Files are embedded at compile time via `include_str!` so failures point
//! directly at committed source, not a runtime filesystem path.

const ROADMAP: &str = include_str!("../../../docs/roadmap-rust.md");
const USER_GUIDE: &str = include_str!("../../../docs/user-guide.md");
const ALPHA_CHECKLIST: &str = include_str!("../../../docs/alpha-release-checklist.md");
const ARCHITECTURE: &str = include_str!("../../../docs/architecture.md");

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
