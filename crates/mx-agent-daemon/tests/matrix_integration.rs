//! Local Matrix integration tests (issues #60 and #61).
//!
//! Exercises the daemon's real Matrix code paths — login, session restore, the
//! long-lived `/sync` loop, sync-token persistence, and event delivery —
//! against a live, throwaway homeserver rather than mocks.
//!
//! [`daemon_e2ee_privileged_event_coverage`] extends this to end-to-end
//! encrypted rooms (issue #61): it proves the daemon decrypts signed
//! `exec`/`call` requests and authorizes them, and that a privileged event the
//! daemon cannot decrypt never reaches authorization and so is not executed.
//!
//! The live orchestration tests (issue #202) run the real daemon paths against
//! the homeserver: [`live_matrix_backed_remote_call_round_trips`] and
//! [`live_matrix_backed_remote_exec_round_trips_and_denies`] cover signed
//! remote `call`/`exec` (streaming, stdin, and policy denial), and
//! [`live_scheduler_executes_signed_task_dag_and_denies`] drives the live
//! daemon scheduler loop over real `com.mxagent.task.v1` room state — auto
//! executing a signed, assigned task DAG (honoring dependencies), refusing a
//! policy-denied action, holding an approval-required action until it is decided
//! over IPC (approve → runs to `succeeded`; deny → `blocked`, never spawned) —
//! so none of those spawn a process they should not.
//!
//! [`two_daemons_discover_each_other_and_compute_liveness`] (issues #227, #250)
//! adds a focused two-daemon discovery + liveness contract test: two independent
//! daemons (distinct signing identities) register in one room, each discovers
//! the other's `com.mxagent.agent.v1` state, a real heartbeat refreshes the
//! durable liveness state, and the `LivenessConfig` thresholds drive the
//! Active → Stale → Offline transition deterministically off an injected clock.
//! Issue #250 extends this: `read_latest_heartbeats` is exercised against the
//! live timeline, `liveness_combined` is verified to lift Offline to Active via
//! a fresh timeline heartbeat, and the new `AgentListing` IPC envelope shape
//! (`{ "agent": AgentState, "liveness": "active"|"stale"|"offline" }`) is pinned.
//!
//! The E2EE durability/verification tests (issue #260, extending #240) cover the
//! three highest-value transport properties end-to-end against a real homeserver:
//! [`live_decrypt_after_restart_from_persistent_store`] drops a daemon's client
//! and rebuilds it from the *same* device-keyed crypto store, proving the resumed
//! device decrypts a message that was encrypted while it was down;
//! [`live_key_backup_restore_across_reprovision`] enables server-side key backup,
//! re-provisions onto a fresh device with an empty store that cannot decrypt
//! history, and proves `recover` restores decryptability; and
//! [`live_two_daemon_sas_confirms_and_verifies`] drives the interactive emoji/SAS
//! flow between two independent daemons to a mutual `confirmed` and asserts
//! `sender_verified == Some(true)` on both sides. The backup and SAS tests read
//! optional fresh-per-run users
//! (`MX_AGENT_TEST_BACKUP_USER`/`_PASSWORD`, `MX_AGENT_TEST_SAS_USER`/`_PASSWORD`,
//! `MX_AGENT_TEST_SAS_USER2`/`_PASSWORD2`) provisioned by the harness, falling
//! back to the shared users when unset.
//!
//! [`workspace_create_with_e2ee_enables_encryption_and_routes_privileged_events`]
//! (issue #249) proves the encrypted-on-create workspace path end-to-end: a
//! [`create_workspace`] call with `e2ee: true` returns `encrypted: true` immediately,
//! the live room reports `is_encrypted() == true` after the first sync, and a
//! signed privileged event posted into the workspace decrypts correctly at the
//! daemon and authorizes through the real pipeline — proving encryption-on-create
//! composes with the existing fail-safe receive path. The unencrypted counterpart is
//! covered by [`workspace_room_is_created_without_encryption`].
//!
//! [`live_result_plane_forge_is_rejected`] (issue #304) proves the result-plane
//! sender-pin gate end-to-end against a real homeserver: Bob (the requester) also
//! acts as an adversarial forger and publishes a `com.mxagent.exec.finished.v1`
//! event carrying a fake exit code (42) **and** a `com.mxagent.stream.chunk.v1`
//! with distinctive injected payload immediately after sending a signed exec
//! request to Alice (the executor). The real command exits with code 77. The
//! daemon's `ExecSubscriberRegistry` pins the subscription to Alice's Matrix user
//! id; both of Bob's forged events are dropped by the sender-pin check and the
//! subscription delivers only Alice's real result (exit 77, no forged chunks).
//! This test exercises the full path for both attack vectors:
//! Matrix SDK event delivery → sync loop routing → `publish_forwarded` →
//! subscriber sender-pin → consumer, proving "room membership ≠ execution
//! permission" for the result plane (fake exit status **and** injected output).
//!
//! Five tests (issue #306) prove the live `exec`/`call` approval-release path
//! end-to-end against a real homeserver:
//! [`live_exec_held_approval_approve_releases_and_runs`] — approve a held live
//! `exec` via [`decide_approval_for_session`] → `handle_live_approval_decision`
//! re-authorizes and spawns it, the sentinel file appears, the queue entry is
//! removed; [`live_exec_held_approval_deny_never_runs`] — deny a held live `exec`
//! → the command never spawns, the queue entry is still removed (terminal denial);
//! [`live_call_held_approval_approve_releases_and_runs`] — approve a held live
//! `call` → `release_held_call` runs the tool and a `call.response.v1` appears in
//! the room timeline; [`live_exec_held_forged_decision_ignored`] — Bob emits an
//! unsigned `approval.decision.v1` for Alice's held exec → the sender check
//! (`untrusted_sender`) drops it, the hold stays queued, the exec never runs;
//! [`live_exec_held_expiry_never_runs`] — a pre-injected live exec hold whose
//! `expires_at` is already past is swept by the scheduler's
//! `sweep_expired_live_holds` on its first pass, the queue entry is removed, and
//! the command sentinel is never created (mirrors #291 for task-backed holds).
//!
//! Four more tests (issue #309) prove the trust-store anchor for approval
//! decisions end-to-end against a real homeserver:
//! [`live_scheduler_rejects_decision_with_untrusted_key`] — a decision signed
//! by a key that IS published in `com.mxagent.agent.v1` room state but is NOT
//! in Alice's local trust store is rejected (`untrusted_key`) and the held task
//! is never released, proving room-published state is never the sole key anchor;
//! [`live_scheduler_rejects_expired_decision`] — a decision signed with the
//! daemon's own key but stamped with an `expires_at` in the past is rejected
//! (`decision_expired`) cache-independently (the check lives in
//! `verification_failure`, before any replay cache is consulted);
//! [`live_approval_window_expiry_blocks_task`] — a held task whose queued
//! `expires_at` has already passed transitions to `blocked(approval_expired)`
//! without any decision being issued; and
//! [`live_approver_allowlist_releases_task`] — a non-daemon Matrix user
//! configured in the room's `approvers` policy can release a task when their
//! signing key is locally trusted, while the daemon's own account remains the
//! authorized default when no allowlist is configured.
//!
//! It is `#[ignore]`d so the default `cargo test --all` (which has no
//! homeserver) stays green. Run it through the documented harness:
//!
//! ```bash
//! scripts/matrix_integration_test.sh
//! ```
//!
//! which boots the local homeserver (issue #59), registers the two test users,
//! and sets the environment variables this test reads:
//!
//! - `MX_AGENT_TEST_HOMESERVER` — homeserver base URL (e.g. `http://127.0.0.1:8008`)
//! - `MX_AGENT_TEST_USER` / `MX_AGENT_TEST_PASSWORD` — the daemon-side user
//! - `MX_AGENT_TEST_USER2` / `MX_AGENT_TEST_PASSWORD2` — a second user whose
//!   message the daemon must observe over `/sync`
//! - `MX_AGENT_TEST_RECOVERY_USER` / `_PASSWORD` — a fresh-per-run user with a
//!   pristine cross-signing identity for the recovery/key-backup tests
//! - `MX_AGENT_TEST_BACKUP_USER` / `_PASSWORD` — a fresh-per-run user (clean
//!   backup version) for [`live_key_backup_restore_across_reprovision`]
//! - `MX_AGENT_TEST_SAS_USER` / `_PASSWORD` and
//!   `MX_AGENT_TEST_SAS_USER2` / `_PASSWORD2` — fresh-per-run single-device peers
//!   for [`live_two_daemon_sas_confirms_and_verifies`]
//! - `MX_AGENT_TEST_LOGREDACT_USER` / `_PASSWORD` — a fresh-per-run user (pristine
//!   cross-signing) for the process-level
//!   [`live_no_secrets_in_daemon_log_after_login_and_recover`]; falls back to the
//!   recovery user, then the shared user, when unset

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use std::time::Duration;

use matrix_sdk::config::SyncSettings;
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::ruma::api::client::room::{create_room, Visibility};
use matrix_sdk::ruma::events::key::verification::request::ToDeviceKeyVerificationRequestEvent;
use matrix_sdk::ruma::events::room::member::MembershipState;
use matrix_sdk::ruma::events::room::message::{
    OriginalSyncRoomMessageEvent, RoomMessageEventContent,
};
use matrix_sdk::ruma::{EventId, OwnedRoomId, UserId};
use matrix_sdk::{Client, Room};
use serde_json::{json, Value};

use mx_agent_daemon::session::ENV_DATA_DIR;
use mx_agent_daemon::{
    approval_decision_for, authorize_call_request, authorize_exec_request,
    build_signed_call_request, build_signed_call_request_for_target, build_signed_exec_request,
    cancel_task_for_session, create_task, create_task_for_session, create_workspace,
    decide_approval_for_session, diagnose_tasks, emit_approval_decision, emit_heartbeat,
    encode_verifying_key, fetch_context, get_invocation, grant_workspace, key_id_for_verifying_key,
    list_agents, list_agents_with_liveness_for_session, list_pending_approvals, list_tasks,
    load_or_create_signing_key, load_sync_token, login_password, read_latest_heartbeats,
    register_agent, restore_client, retrieve_artifact, run_matrix_sync,
    run_matrix_sync_with_subscribers, run_scheduler_loop, save_session, share_context, show_agent,
    sign_task_action, start_call_matrix, start_exec_matrix, AgentListing, ApprovalQueue,
    BackoffConfig, CallOutcome, CallStartParams, CallTargeting, CreateTaskOptions,
    CreateWorkspaceOptions, DaemonSigningKey, ExecFrame, ExecOutcome, ExecRequestOptions,
    ExecStartParams, ExecSubscriberRegistry, ExecSubscriptionKey, FetchContextOptions,
    ForwardedExecEvent, GrantWorkspaceOptions, HeartbeatConfig, HeldRequest, ListAgentsOptions,
    ListTasksOptions, Liveness, LivenessConfig, MatrixConfig, PendingApproval, PtyWinsize,
    RecoveryEnableResult, RegisterAgentOptions, RetrieveArtifactOptions, SasAdvance, SessionPaths,
    ShareContextOptions, SyncHealth, SyncState, TaskDiagnostic, TaskDispatchMode, TrustStore,
    WorkspaceError, WorkspaceVisibility, DECISION_APPROVED, DECISION_DENIED,
    DEFAULT_ARTIFACT_SCAN_LIMIT, HEARTBEAT_SCAN_LIMIT, MAX_HEARTBEAT_SCAN_EVENTS,
    WORKSPACE_AGENT_PL,
};
use mx_agent_policy::Policy;
use mx_agent_protocol::events::timeline;
use mx_agent_protocol::schema::{
    AgentState, ApprovalRequest, ExecRequest, Signature, StreamKind, TaskAction,
};

/// Read a required environment variable or fail with an actionable message.
fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "{name} is not set; run this test via scripts/matrix_integration_test.sh, \
             which boots a local homeserver and registers the test users"
        )
    })
}

/// A unique, throwaway data directory so persisted sync-token state for this
/// run never collides with other runs or a real install.
fn throwaway_data_dir() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "mx-agent-it-matrix-{}-{}",
        std::process::id(),
        nanos
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn daemon_syncs_and_receives_events_from_live_homeserver() {
    let _serial = enter_single_threaded_section();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    // Isolate the daemon's persisted sync token in a throwaway data dir.
    std::env::set_var(ENV_DATA_DIR, throwaway_data_dir());
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };

    // Daemon-side login then session restore — the real daemon startup path.
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login should succeed");
    let alice = restore_client(&alice_session)
        .await
        .expect("alice session restore should succeed");

    // The second user logs in and creates a public room to exchange events in.
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login should succeed");
    let bob = restore_client(&bob_session)
        .await
        .expect("bob session restore should succeed");

    let room = create_public_room(&bob, "mx-agent integration test").await;
    let room_id = room.room_id().to_owned();

    // The daemon user joins the room so it will receive its timeline on sync.
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins room");

    // Capture every `m.room.message` body the daemon observes over `/sync`.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    alice.add_event_handler(move |ev: OriginalSyncRoomMessageEvent| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(ev.content.body().to_owned());
        }
    });

    // Drive the daemon's real `/sync` loop in the background.
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let sync_task = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };

    // The second user posts a uniquely identifiable message.
    let marker = format!("mx-agent-it-{}", std::process::id());
    room.send(RoomMessageEventContent::text_plain(&marker))
        .await
        .expect("bob sends message");

    // The daemon must observe that exact message via its sync loop.
    let observed = tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(body) = rx.recv().await {
            if body == marker {
                return true;
            }
        }
        false
    })
    .await
    .expect("timed out waiting for the daemon to observe the message");
    assert!(observed, "daemon never observed the test message");

    // The sync loop should report healthy progress after a successful sync.
    let healthy = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            {
                let h = health.lock().unwrap();
                if h.state == SyncState::Healthy && h.total_syncs > 0 {
                    return true;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        healthy,
        "sync loop never reported a healthy successful sync"
    );

    // Stop the loop and confirm it persisted a resumable sync token.
    running.store(false, Ordering::SeqCst);
    sync_task
        .await
        .expect("sync task should join")
        .expect("sync loop should exit cleanly");
    let token = load_sync_token(&paths).expect("read sync token");
    assert!(
        token.is_some(),
        "daemon should have persisted a sync token for resume"
    );
}

/// App-level identity of the agent issuing the privileged requests (the
/// requester) — distinct from the Matrix transport users.
const REQUESTER_AGENT: &str = "@requester:mx-agent.test";
/// App-level identity of the daemon that must run (or refuse) the request.
const TARGET_AGENT: &str = "developer-pi";

/// Build session paths rooted at `dir` directly, without touching the
/// process-global `MX_AGENT_DATA_DIR`. This keeps each test's persisted
/// sync-token and signing-key state isolated even when the `#[ignore]`d tests
/// run concurrently in the same binary.
fn paths_in(dir: std::path::PathBuf) -> SessionPaths {
    SessionPaths::for_data_dir(dir)
}

/// Set while a live integration test is executing, so a second overlapping live
/// test can be detected and refused (see [`enter_single_threaded_section`]).
static LIVE_TEST_RUNNING: AtomicBool = AtomicBool::new(false);

/// Acquire the process-global single-thread section for a live test.
///
/// The live suite mutates process-global env (`MX_AGENT_DATA_DIR`,
/// `MX_AGENT_CONFIG_DIR`, …) via dozens of `set_var` calls and is correct only
/// when test functions run one at a time, so it MUST be driven through
/// `scripts/matrix_integration_test.sh`, which passes `--test-threads=1`. A bare
/// `cargo test -p mx-agent-daemon --test matrix_integration -- --ignored` runs
/// the tests in parallel and would silently race those mutations.
///
/// Every `#[ignore]` live test acquires this guard as its first statement. If
/// two ever overlap (i.e. the suite was run multi-threaded), the second
/// acquisition panics with a pointer to the wrapper script instead of racing.
/// The guard releases on drop — including during panic unwind — so a failing
/// test never poisons later runs. Uses only `AtomicBool` + RAII `Drop`; no
/// `unsafe` (the workspace forbids it).
#[must_use]
fn enter_single_threaded_section() -> SingleThreadGuard {
    if LIVE_TEST_RUNNING.swap(true, Ordering::SeqCst) {
        panic!(
            "two live integration tests are running concurrently; this suite \
             mutates process-global env and MUST run single-threaded. Run it \
             via scripts/matrix_integration_test.sh (which passes \
             --test-threads=1), not a bare `cargo test -- --ignored`."
        );
    }
    SingleThreadGuard
}

/// RAII release token for [`enter_single_threaded_section`]; clears
/// `LIVE_TEST_RUNNING` on drop.
struct SingleThreadGuard;

impl Drop for SingleThreadGuard {
    fn drop(&mut self) {
        LIVE_TEST_RUNNING.store(false, Ordering::SeqCst);
    }
}

/// Unit-level coverage for [`enter_single_threaded_section`]: a second
/// acquisition while the first is still held must panic, and the section must be
/// re-acquirable once the first guard drops. Runs in the default `cargo test`
/// (it is **not** `#[ignore]`d) and never overlaps the live tests, which only
/// run under `--ignored`.
#[test]
fn single_thread_guard_trips_on_overlap() {
    let held = enter_single_threaded_section(); // first acquisition holds the flag
    let res = std::panic::catch_unwind(|| {
        let _g = enter_single_threaded_section();
    });
    assert!(res.is_err(), "second concurrent acquisition must panic");
    drop(held);
    // The flag is released; a fresh acquisition now succeeds.
    let _g = enter_single_threaded_section();
}

/// A receive-side policy that trusts `room_id` and permits the requester to run
/// the `cargo` exec and the `run_tests` call exercised by the E2EE test. This
/// mirrors the policy fixtures used by the `exec`/`call` unit tests, with the
/// room id bound to the live room created during the test.
fn permissive_policy(room_id: &str, agent: &str) -> Policy {
    let toml = format!(
        r#"
[rooms."{room_id}"]
trusted = true

[rooms."{room_id}".agents."{agent}"]
allow_exec = true
allow_commands = ["cargo"]
allow_cwd = ["/home/me/code/project"]
allow_tools = ["run_tests"]
"#
    );
    Policy::parse(&toml).expect("policy fixture parses")
}

/// The exec command the requester asks the target to run.
fn exec_options() -> ExecRequestOptions {
    ExecRequestOptions {
        target_agent: TARGET_AGENT.to_string(),
        requesting_agent: REQUESTER_AGENT.to_string(),
        command: vec!["cargo".to_string(), "test".to_string()],
        cwd: "/home/me/code/project".to_string(),
        env: BTreeMap::new(),
        stdin: false,
        stream: true,
        pty: false,
        timeout_ms: 600_000,
        task_id: None,
    }
}

/// Maximum attempts for transient homeserver operations that can briefly race
/// with the server's own state resolution.
const MAX_CREATE_ATTEMPTS: u32 = 5;

/// Create a public chat room, retrying transient homeserver errors.
///
/// Conduit-family homeservers (Tuwunel) can briefly return a 403
/// ("sender's membership `leave` is not `join`") right after `create_room`
/// while the creator's own join membership is still settling — more likely
/// under concurrent load. Public + PublicChat lets the daemon user later
/// `join_room_by_id`, and the default `shared` history visibility lets a late
/// joiner fetch (but not decrypt) earlier events. Retrying with a short backoff
/// removes the flake.
async fn create_public_room(client: &Client, name: &str) -> Room {
    for attempt in 1..=MAX_CREATE_ATTEMPTS {
        let mut create = create_room::v3::Request::new();
        create.name = Some(name.to_owned());
        create.visibility = Visibility::Public;
        create.preset = Some(create_room::v3::RoomPreset::PublicChat);
        match client.create_room(create).await {
            Ok(room) => return room,
            Err(e) if attempt < MAX_CREATE_ATTEMPTS => {
                eprintln!("create_room {name:?} attempt {attempt} failed: {e}; retrying");
                tokio::time::sleep(Duration::from_millis(400 * u64::from(attempt))).await;
            }
            Err(e) => {
                panic!("create_room {name:?} failed after {MAX_CREATE_ATTEMPTS} attempts: {e}")
            }
        }
    }
    unreachable!("loop either returns a room or panics")
}

/// Create a public, end-to-end encrypted room owned by `client`.
///
/// `enable_encryption` sends the `m.room.encryption` state event and waits for
/// a sync to reflect it, so the caller must already be running a sync loop. Both
/// the room creation and the encryption enablement retry transient errors.
async fn create_encrypted_room(client: &Client, name: &str) -> Room {
    let room = create_public_room(client, name).await;
    for attempt in 1..=MAX_CREATE_ATTEMPTS {
        match room.enable_encryption().await {
            Ok(()) => break,
            Err(e) if attempt < MAX_CREATE_ATTEMPTS => {
                eprintln!("enable_encryption attempt {attempt} failed: {e}; retrying");
                tokio::time::sleep(Duration::from_millis(400 * u64::from(attempt))).await;
            }
            Err(e) => panic!(
                "enable end-to-end encryption failed after {MAX_CREATE_ATTEMPTS} attempts: {e}"
            ),
        }
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if room.encryption_state().is_encrypted() {
                return;
            }
            let _ = client.sync_once(SyncSettings::default()).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("room should report encryption enabled");
    room
}

/// Block until `user` is observed as a joined member of `room`, so a subsequent
/// encrypted send shares the megolm room key with that user's device.
async fn wait_for_joined_member(room: &Room, user: &UserId) {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Ok(Some(member)) = room.get_member(user).await {
                if *member.membership() == MembershipState::Join {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("member was never observed as joined");
}

/// Fetch `event_id` from `room`, waiting until the daemon's client can decrypt
/// it, then return its decrypted `content` object. Panics on timeout — a
/// privileged event that never decrypts would be a regression in the E2EE path.
async fn decrypted_content(room: &Room, event_id: &EventId) -> Value {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Ok(event) = room.event(event_id, None).await {
                if event.encryption_info().is_some() {
                    return event
                        .raw()
                        .get_field::<Value>("content")
                        .ok()
                        .flatten()
                        .expect("decrypted timeline event carries a content object");
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("privileged event was never decrypted by the daemon")
}

/// Live Matrix-backed remote call coverage (issues #194, #257).
///
/// Drives two real Matrix users in one room: Bob registers a requester agent,
/// Alice registers the target agent and runs the daemon sync loop, Bob sends a
/// signed targeted call through `start_call_matrix`, and Alice's sync handler
/// verifies signature/trust/policy before executing the tool and emitting a
/// response.
///
/// Issue #257: the test also sends a second call for an unlisted tool ("deploy")
/// and asserts that both decisions — allowed and policy-denied — are written as
/// newline-delimited JSON records to the local audit log, proving that
/// `handle_live_call_request` produces audit entries for all named-call decisions
/// and not only for `exec` decisions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_matrix_backed_remote_call_round_trips() {
    let _serial = enter_single_threaded_section();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");

    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login should succeed");
    let alice = restore_client(&alice_session)
        .await
        .expect("alice session restore should succeed");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login should succeed");
    let bob = restore_client(&bob_session)
        .await
        .expect("bob session restore should succeed");

    let requester_agent = bob.user_id().expect("bob user id").to_string();

    let room = create_public_room(&bob, "mx-agent live call integration test").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": {
                mx_agent_protocol::events::state::AGENT: 50,
            },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester_agent.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["call".to_string()],
            tools: vec!["run_tests@1.0.0".to_string()],
            cwd: "/home/me/code/mx-agent".to_string(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["call".to_string()],
            tools: vec!["run_tests@1.0.0".to_string()],
            cwd: "/home/me/code/mx-agent".to_string(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register target agent");

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_tools = ["run_tests"]
"#,
            room = room_id.as_str(),
            agent = requester_agent,
        ),
    )
    .expect("write policy");

    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };

    // `start_call_matrix` is the daemon IPC implementation side and restores
    // the requester session from disk.
    save_session(&paths, &bob_session).expect("save requester session");
    let result = start_call_matrix(&CallStartParams {
        room: Some(room_id.to_string()),
        agent: Some(TARGET_AGENT.to_string()),
        tool: "run_tests".to_string(),
        input: json!({ "package": "mx-agent-protocol", "name": "canonical" }),
        invocation_id: None,
    })
    .await;

    // Issue #257: send a second call for a tool not in allow_tools — Alice's
    // daemon must audit a denied entry and return an error outcome.
    let denied_result = start_call_matrix(&CallStartParams {
        room: Some(room_id.to_string()),
        agent: Some(TARGET_AGENT.to_string()),
        tool: "deploy".to_string(),
        input: json!({}),
        invocation_id: None,
    })
    .await;

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("sync task joins")
        .expect("sync exits cleanly");

    // Read the audit log before clearing the config-dir env var; the file path
    // is resolved from MX_AGENT_CONFIG_DIR, which is still set here.
    let audit_log_path = config_dir.join(mx_agent_daemon::audit::AUDIT_FILE_NAME);
    let audit_content = std::fs::read_to_string(&audit_log_path)
        .expect("audit log must exist after live calls (issue #257)");

    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");

    match result.outcome {
        CallOutcome::Ok { exit_code, summary } => {
            assert_eq!(exit_code, 0, "remote tool summary: {summary}");
        }
        other => panic!("expected successful remote call, got {other:?}"),
    }
    assert!(
        matches!(denied_result.outcome, CallOutcome::Error { .. }),
        "policy-denied call must return an error outcome, got {:?}",
        denied_result.outcome
    );

    // ── audit log assertions (issue #257) ────────────────────────────────────
    // The daemon must write one JSON-line record for every named-call decision:
    // one allowed entry for run_tests and one denied entry for deploy.
    let audit_records: Vec<serde_json::Value> = audit_content
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("each audit line must be valid JSON"))
        .collect();

    let allowed_entry = audit_records
        .iter()
        .find(|r| r["request"] == "call" && r["decision"] == "allowed" && r["tool"] == "run_tests");
    assert!(
        allowed_entry.is_some(),
        "audit log must contain an allowed call record for run_tests (issue #257):\n{audit_content}"
    );
    let allowed = allowed_entry.unwrap();
    assert_eq!(
        allowed["policy_rule"], "allow_tools",
        "allowed call must record the allow_tools rule: {allowed}"
    );
    assert!(
        !allowed["sandbox"].is_null(),
        "allowed call must record the sandbox backend: {allowed}"
    );
    assert!(
        allowed.get("command").is_none(),
        "call audit record must not carry command argv: {allowed}"
    );

    let denied_entry = audit_records
        .iter()
        .find(|r| r["request"] == "call" && r["decision"] == "denied" && r["tool"] == "deploy");
    assert!(
        denied_entry.is_some(),
        "audit log must contain a denied call record for deploy (issue #257):\n{audit_content}"
    );
    let denied = denied_entry.unwrap();
    assert_eq!(
        denied["policy_rule"], "deny:tool_not_allowed",
        "policy-denied call must record deny:tool_not_allowed: {denied}"
    );
    assert!(
        denied.get("sandbox").is_none(),
        "denied call must not carry a sandbox field: {denied}"
    );
    assert!(
        denied.get("command").is_none(),
        "denied call audit record must not carry command argv: {denied}"
    );
}

/// Live Matrix-backed remote exec coverage (issue #196).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_matrix_backed_remote_exec_round_trips_and_denies() {
    let _serial = enter_single_threaded_section();
    // Enable logging so CI captures daemon decisions on failure (--nocapture).
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");

    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);

    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");
    let denied_file = cwd.join("denied-created");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login should succeed");
    let alice = restore_client(&alice_session)
        .await
        .expect("alice session restore should succeed");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login should succeed");
    let bob = restore_client(&bob_session)
        .await
        .expect("bob session restore should succeed");
    let requester_agent = bob.user_id().expect("bob user id").to_string();

    let room = create_public_room(&bob, "mx-agent live exec integration test").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester_agent.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register target agent");

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
"#,
            room = room_id.as_str(),
            agent = requester_agent,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    let subscribers = ExecSubscriberRegistry::new();
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &alice,
                &paths,
                health,
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };
    // Bob/requester also needs a sync loop to receive target stream events and
    // publish them into the same test registry used by start_exec_matrix.
    let bob_sync_paths = paths_in(data_dir.join("bob-sync"));
    bob_sync_paths
        .ensure_data_dir()
        .expect("create bob sync dir");
    let bob_sync = {
        let bob = bob.clone();
        let paths = bob_sync_paths.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &bob,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };

    save_session(&paths, &bob_session).expect("save requester session");
    let result = start_exec_matrix(
        &ExecStartParams {
            room: Some(room_id.to_string()),
            agent: Some(TARGET_AGENT.to_string()),
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo hello; echo err >&2; exit 7".to_string(),
            ],
            cwd: Some(cwd.clone()),
            stdin: None,
            stream: true,
            pty: false,
            task: None,
            strict_stream: false,
            env: Default::default(),
            timeout_ms: None,
            invocation_id: None,
        },
        &subscribers,
    )
    .await;

    match result.outcome {
        ExecOutcome::Ok { frames } => {
            assert!(frames
                .iter()
                .any(|f| matches!(f, ExecFrame::Chunk(c) if c.data.contains("hello"))));
            assert!(frames
                .iter()
                .any(|f| matches!(f, ExecFrame::Chunk(c) if c.data.contains("err"))));
            assert!(
                matches!(frames.last(), Some(ExecFrame::Finished(f)) if f.exit_code == Some(7))
            );
        }
        other => panic!("expected remote exec output, got {other:?}"),
    }

    let stdin_result = start_exec_matrix(
        &ExecStartParams {
            room: Some(room_id.to_string()),
            agent: Some(TARGET_AGENT.to_string()),
            command: vec!["sh".to_string(), "-c".to_string(), "cat".to_string()],
            cwd: Some(cwd.clone()),
            stdin: Some(b"stdin over matrix\n".to_vec()),
            stream: true,
            pty: false,
            task: None,
            strict_stream: false,
            env: Default::default(),
            timeout_ms: None,
            invocation_id: None,
        },
        &subscribers,
    )
    .await;
    match stdin_result.outcome {
        ExecOutcome::Ok { frames } => {
            assert!(frames
                .iter()
                .any(|f| matches!(f, ExecFrame::Chunk(c) if c.data.contains("stdin over matrix"))));
            assert!(
                matches!(frames.last(), Some(ExecFrame::Finished(f)) if f.exit_code == Some(0))
            );
        }
        other => panic!("expected remote stdin output, got {other:?}"),
    }

    let denied = start_exec_matrix(
        &ExecStartParams {
            room: Some(room_id.to_string()),
            agent: Some(TARGET_AGENT.to_string()),
            command: vec![
                "touch".to_string(),
                denied_file.to_string_lossy().into_owned(),
            ],
            cwd: Some(cwd.clone()),
            stdin: None,
            stream: true,
            pty: false,
            task: None,
            strict_stream: false,
            env: Default::default(),
            timeout_ms: None,
            invocation_id: None,
        },
        &subscribers,
    )
    .await;
    assert!(matches!(denied.outcome, ExecOutcome::Error { .. }));
    assert!(!denied_file.exists(), "policy-denied exec must not spawn");

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync task joins")
        .expect("alice sync exits cleanly");
    bob_sync
        .await
        .expect("bob sync task joins")
        .expect("bob sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");
}

/// Live non-PTY exec output-cap: `exec.finished.truncated` carries the real value (issue #268).
///
/// Two daemons over the live homeserver. The target's policy sets `max_output_bytes = 10`:
/// a command that produces more than 10 bytes must yield `truncated: true` in the forwarded
/// `ExecFinished`, while a small-output command within the cap must yield `truncated: false`.
/// This validates that the live non-PTY path threads the `CaptureSummary.truncated` flag
/// through `emit_output_events` → `ExecFinished` rather than hardcoding `false`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_non_pty_exec_truncation_is_reported() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester_agent = bob.user_id().expect("bob user id").to_string();

    let room = create_public_room(&bob, "mx-agent live exec truncation test").await;
    let room_id = room.room_id().to_owned();
    alice.join_room_by_id(&room_id).await.expect("alice joins");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    for (client, agent_id) in [
        (&bob, requester_agent.clone()),
        (&alice, TARGET_AGENT.to_string()),
    ] {
        register_agent(
            client,
            &RegisterAgentOptions {
                room: room_id.to_string(),
                agent_id: Some(agent_id),
                kind: "pi".to_string(),
                capabilities: vec!["exec".to_string()],
                tools: vec![],
                cwd: cwd.to_string_lossy().into_owned(),
                project_id: "mx-agent-it".to_string(),
                max_invocations: 1,
            },
        )
        .await
        .expect("register agent");
    }

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    // 10-byte output cap: any command producing more than 10 bytes must trigger truncation.
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
max_output_bytes = 10
"#,
            room = room_id.as_str(),
            agent = requester_agent,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    let subscribers = ExecSubscriberRegistry::new();
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &alice,
                &paths,
                health,
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };
    let bob_sync_paths = paths_in(data_dir.join("bob-sync"));
    bob_sync_paths
        .ensure_data_dir()
        .expect("create bob sync dir");
    let bob_sync = {
        let bob = bob.clone();
        let paths = bob_sync_paths.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &bob,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };

    save_session(&paths, &bob_session).expect("save requester session");

    // Command that produces ~50 bytes — well over the 10-byte cap.
    let over_cap = start_exec_matrix(
        &ExecStartParams {
            room: Some(room_id.to_string()),
            agent: Some(TARGET_AGENT.to_string()),
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf '%050d' 0".to_string(),
            ],
            cwd: Some(cwd.clone()),
            stdin: None,
            stream: true,
            pty: false,
            task: None,
            strict_stream: false,
            env: Default::default(),
            timeout_ms: None,
            invocation_id: None,
        },
        &subscribers,
    )
    .await;
    match over_cap.outcome {
        ExecOutcome::Ok { ref frames } => {
            let finished = frames
                .iter()
                .find_map(|f| {
                    if let ExecFrame::Finished(fin) = f {
                        Some(fin)
                    } else {
                        None
                    }
                })
                .expect("over-cap exec must have a Finished frame");
            assert!(
                finished.truncated,
                "output exceeding max_output_bytes must yield truncated:true; got {finished:?}"
            );
        }
        other => panic!("expected Ok for over-cap exec, got {other:?}"),
    }

    // Command that produces 3 bytes ("hi\n") — within the 10-byte cap.
    let within_cap = start_exec_matrix(
        &ExecStartParams {
            room: Some(room_id.to_string()),
            agent: Some(TARGET_AGENT.to_string()),
            command: vec!["sh".to_string(), "-c".to_string(), "echo hi".to_string()],
            cwd: Some(cwd.clone()),
            stdin: None,
            stream: true,
            pty: false,
            task: None,
            strict_stream: false,
            env: Default::default(),
            timeout_ms: None,
            invocation_id: None,
        },
        &subscribers,
    )
    .await;
    match within_cap.outcome {
        ExecOutcome::Ok { ref frames } => {
            let finished = frames
                .iter()
                .find_map(|f| {
                    if let ExecFrame::Finished(fin) = f {
                        Some(fin)
                    } else {
                        None
                    }
                })
                .expect("within-cap exec must have a Finished frame");
            assert!(
                !finished.truncated,
                "output within max_output_bytes must yield truncated:false; got {finished:?}"
            );
        }
        other => panic!("expected Ok for within-cap exec, got {other:?}"),
    }

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync task joins")
        .expect("alice sync exits cleanly");
    bob_sync
        .await
        .expect("bob sync task joins")
        .expect("bob sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");
}

/// Live Matrix-backed remote interactive PTY exec coverage (issue #238).
///
/// Two daemons over the live homeserver: the requester (bob) sends a signed
/// `exec.request{pty:true}` to the target (alice), which allocates a real
/// pseudo-terminal, live-streams the merged terminal output as `stream:"pty"`
/// chunks, and applies a `pty.resize` window-size hint. The command prints its
/// terminal size after the resize lands, proving both PTY streaming over the
/// signed transport and resize propagation. Authorization is the same signed
/// pipeline as non-PTY exec.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_matrix_backed_remote_pty_streams_and_resizes() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester_agent = bob.user_id().expect("bob user id").to_string();

    let room = create_public_room(&bob, "mx-agent live pty integration test").await;
    let room_id = room.room_id().to_owned();
    alice.join_room_by_id(&room_id).await.expect("alice joins");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    for (client, agent_id) in [
        (&bob, requester_agent.clone()),
        (&alice, TARGET_AGENT.to_string()),
    ] {
        register_agent(
            client,
            &RegisterAgentOptions {
                room: room_id.to_string(),
                agent_id: Some(agent_id),
                kind: "pi".to_string(),
                capabilities: vec!["exec".to_string()],
                tools: vec![],
                cwd: cwd.to_string_lossy().into_owned(),
                project_id: "mx-agent-it".to_string(),
                max_invocations: 1,
            },
        )
        .await
        .expect("register agent");
    }

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
"#,
            room = room_id.as_str(),
            agent = requester_agent,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    let subscribers = ExecSubscriberRegistry::new();
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &alice,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };
    let bob_sync_paths = paths_in(data_dir.join("bob-sync"));
    bob_sync_paths.ensure_data_dir().expect("bob sync dir");
    let bob_sync = {
        let bob = bob.clone();
        let paths = bob_sync_paths.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &bob,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };

    // Send a signed PTY exec request: print the terminal size after a short
    // delay, so a resize sent meanwhile is reflected in the output.
    let invocation_id = format!("inv_pty_{}", std::process::id());
    let options = ExecRequestOptions {
        target_agent: TARGET_AGENT.to_string(),
        requesting_agent: requester_agent.clone(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            "sleep 1; stty size".to_string(),
        ],
        cwd: cwd.to_string_lossy().into_owned(),
        env: Default::default(),
        stdin: true,
        stream: true,
        pty: true,
        timeout_ms: 600_000,
        task_id: None,
    };
    let content = build_signed_exec_request(
        signing.signing_key(),
        signing.key_id(),
        &invocation_id,
        format!("req_pty_{}", std::process::id()),
        format!("pty-nonce-{}", std::process::id()),
        "2026-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        &options,
    )
    .expect("sign pty exec request");

    // Pin the subscription to the executing agent (alice runs TARGET_AGENT), so
    // only the real executor's stream/result events resolve it (issue #304).
    let mut subscription = subscribers.subscribe(
        ExecSubscriptionKey::Invocation(invocation_id.clone()),
        alice_id.to_string(),
    );
    room.send_raw(timeline::EXEC_REQUEST, content)
        .await
        .expect("send pty exec request");

    // Give the target time to register the live control, then resize.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    mx_agent_daemon::send_pty_resize(
        &room,
        signing.signing_key(),
        signing.key_id(),
        &invocation_id,
        PtyWinsize::new(50, 132),
    )
    .await
    .expect("send pty resize");

    // Collect merged PTY output until the invocation finishes.
    let mut output = String::new();
    let mut finished = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_secs(5), subscription.recv()).await {
            Ok(Some(ForwardedExecEvent::StreamChunk(chunk))) if chunk.stream == StreamKind::Pty => {
                let bytes = if chunk.encoding == "base64" {
                    base64::engine::general_purpose::STANDARD
                        .decode(chunk.data.as_bytes())
                        .unwrap_or_default()
                } else {
                    chunk.data.into_bytes()
                };
                output.push_str(&String::from_utf8_lossy(&bytes));
            }
            Ok(Some(ForwardedExecEvent::ExecFinished(_))) => {
                finished = true;
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    running.store(false, Ordering::SeqCst);
    let _ = alice_sync.await.expect("alice sync joins");
    let _ = bob_sync.await.expect("bob sync joins");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");

    assert!(
        finished,
        "remote PTY invocation should finish; got output {output:?}"
    );
    assert!(
        output.contains("50 132"),
        "resize should propagate over the transport to the remote PTY: {output:?}"
    );
}

/// Live PTY exec output-cap: `exec.finished.truncated` reflects the real cap (issue #268).
///
/// Two daemons over the live homeserver. The target's policy sets `max_output_bytes = 10`
/// so a PTY command that outputs more than 10 bytes must produce `truncated: true` in the
/// forwarded `ExecFinished`. This validates the live PTY path (`run_controlled_pty_exec`
/// chunker → `PtyExecOutcome.truncated` → `exec.finished`) rather than hardcoding `false`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_pty_exec_truncation_is_reported() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester_agent = bob.user_id().expect("bob user id").to_string();

    let room = create_public_room(&bob, "mx-agent live pty truncation test").await;
    let room_id = room.room_id().to_owned();
    alice.join_room_by_id(&room_id).await.expect("alice joins");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    for (client, agent_id) in [
        (&bob, requester_agent.clone()),
        (&alice, TARGET_AGENT.to_string()),
    ] {
        register_agent(
            client,
            &RegisterAgentOptions {
                room: room_id.to_string(),
                agent_id: Some(agent_id),
                kind: "pi".to_string(),
                capabilities: vec!["exec".to_string()],
                tools: vec![],
                cwd: cwd.to_string_lossy().into_owned(),
                project_id: "mx-agent-it".to_string(),
                max_invocations: 1,
            },
        )
        .await
        .expect("register agent");
    }

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    // 10-byte output cap on the PTY path — any PTY output > 10 bytes must truncate.
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
max_output_bytes = 10
"#,
            room = room_id.as_str(),
            agent = requester_agent,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    let subscribers = ExecSubscriberRegistry::new();
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &alice,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };
    let bob_sync_paths = paths_in(data_dir.join("bob-sync"));
    bob_sync_paths.ensure_data_dir().expect("bob sync dir");
    let bob_sync = {
        let bob = bob.clone();
        let paths = bob_sync_paths.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &bob,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };

    // Sign and send a PTY exec request for a command that outputs ~50 bytes.
    let invocation_id = format!("inv_pty_trunc_{}", std::process::id());
    let options = ExecRequestOptions {
        target_agent: TARGET_AGENT.to_string(),
        requesting_agent: requester_agent.clone(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            "printf '%050d' 0".to_string(),
        ],
        cwd: cwd.to_string_lossy().into_owned(),
        env: Default::default(),
        stdin: false,
        stream: true,
        pty: true,
        timeout_ms: 600_000,
        task_id: None,
    };
    let content = build_signed_exec_request(
        signing.signing_key(),
        signing.key_id(),
        &invocation_id,
        format!("req_pty_trunc_{}", std::process::id()),
        format!("pty-trunc-nonce-{}", std::process::id()),
        "2026-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        &options,
    )
    .expect("sign pty exec request");

    // Pin the subscription to the executing agent (alice runs TARGET_AGENT).
    let mut subscription = subscribers.subscribe(
        ExecSubscriptionKey::Invocation(invocation_id.clone()),
        alice_id.to_string(),
    );
    room.send_raw(timeline::EXEC_REQUEST, content)
        .await
        .expect("send pty exec request");

    // Collect events until ExecFinished or deadline.
    let mut truncated_result: Option<bool> = None;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_secs(5), subscription.recv()).await {
            Ok(Some(ForwardedExecEvent::ExecFinished(finished))) => {
                truncated_result = Some(finished.truncated);
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    running.store(false, Ordering::SeqCst);
    let _ = alice_sync.await.expect("alice sync joins");
    let _ = bob_sync.await.expect("bob sync joins");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");

    let truncated =
        truncated_result.expect("PTY exec must deliver ExecFinished before the 30 s deadline");
    assert!(
        truncated,
        "PTY output exceeding max_output_bytes must yield truncated:true"
    );
}

/// End-to-end encryption coverage for privileged events (issue #61).
///
/// Runs entirely against the live local homeserver booted by
/// `scripts/matrix_integration_test.sh`, driving the daemon's real client
/// (login → restore → `/sync`) through **encrypted** rooms. It proves the two
/// acceptance criteria:
///
/// 1. *Encrypted exec/call metadata works in the test harness.* The requester
///    sends signed `exec`/`call` requests into an encrypted room; the daemon
///    decrypts them over `/sync` and the decrypted content passes the real
///    receive-side authorization pipeline ([`authorize_exec_request`] /
///    [`authorize_call_request`]).
/// 2. *Undecryptable privileged events are not executed.* A signed `exec`
///    request sent before the daemon joined the room arrives as an
///    `m.room.encrypted` event the daemon cannot decrypt. It therefore never
///    surfaces a `com.mxagent.exec.request.v1` typed event, so authorization is
///    never reached and nothing runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn daemon_e2ee_privileged_event_coverage() {
    let _serial = enter_single_threaded_section();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    // Isolate this test's persisted state (sync token, signing key) without
    // mutating the process-global data-dir env var.
    let paths = paths_in(throwaway_data_dir());
    paths.ensure_data_dir().expect("create data dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };

    // The daemon (Alice) logs in and restores a session — the real startup path.
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login should succeed");
    let alice = restore_client(&alice_session)
        .await
        .expect("alice session restore should succeed");

    // The requester (Bob) drives the events the daemon must observe.
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login should succeed");
    let bob = restore_client(&bob_session)
        .await
        .expect("bob session restore should succeed");

    // Drive the daemon's real `/sync` loop: it uploads device/one-time keys and
    // decrypts incoming encrypted events.
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };

    // The requester also needs a live sync so its crypto state (device keys,
    // to-device key sharing) is established before it sends.
    let bob_sync = {
        let bob = bob.clone();
        tokio::spawn(async move {
            let _ = bob.sync(SyncSettings::default()).await;
        })
    };

    // The requester's signing identity, plus a trust store that accepts it.
    let signing = load_or_create_signing_key(&paths).expect("requester signing key");
    let key_id = signing.key_id();
    let verifying = signing.verifying_key();
    let mut trust = TrustStore::default();
    trust.approve(REQUESTER_AGENT, &key_id, None, None, None);

    let alice_id = alice.user_id().expect("alice has a user id").to_owned();

    // ---- Criterion 1: encrypted exec/call metadata works ----
    let room = create_encrypted_room(&bob, "mx-agent E2EE integration test").await;
    let room_id = room.room_id().to_owned();
    let alice_room = alice
        .join_room_by_id(&room_id)
        .await
        .expect("daemon joins encrypted room");
    // The requester must see the daemon as joined before sending, so the megolm
    // room key is shared with the daemon's device.
    wait_for_joined_member(&room, &alice_id).await;

    let policy = permissive_policy(room_id.as_str(), REQUESTER_AGENT);

    // Encrypted, signed exec request → daemon decrypts → authorization succeeds.
    let exec_content = build_signed_exec_request(
        signing.signing_key(),
        &key_id,
        "inv_e2ee_exec",
        "req_e2ee_exec",
        "e2ee-exec-nonce",
        "2026-06-04T12:00:00Z",
        "2026-06-04T12:05:00Z",
        &exec_options(),
    )
    .expect("sign exec request");
    let exec_event_id = room
        .send_raw(timeline::EXEC_REQUEST, exec_content)
        .await
        .expect("send encrypted exec request")
        .response
        .event_id;
    let exec_decrypted = decrypted_content(&alice_room, &exec_event_id).await;
    let authorized_exec = authorize_exec_request(
        &exec_decrypted,
        &verifying,
        &trust,
        &policy,
        room_id.as_str(),
        REQUESTER_AGENT,
        TARGET_AGENT,
    )
    .expect("decrypted exec metadata should authorize");
    assert_eq!(authorized_exec.invocation_id, "inv_e2ee_exec");
    assert_eq!(authorized_exec.command, vec!["cargo", "test"]);

    // Encrypted, signed call request → daemon decrypts → authorization succeeds.
    let call_content = build_signed_call_request(
        signing.signing_key(),
        &key_id,
        "inv_e2ee_call",
        "req_e2ee_call",
        "run_tests",
        json!({ "suite": "integration" }),
    )
    .expect("sign call request");
    let call_event_id = room
        .send_raw(timeline::CALL_REQUEST, call_content)
        .await
        .expect("send encrypted call request")
        .response
        .event_id;
    let call_decrypted = decrypted_content(&alice_room, &call_event_id).await;
    let authorized_call = authorize_call_request(
        &call_decrypted,
        &verifying,
        &trust,
        &policy,
        room_id.as_str(),
        REQUESTER_AGENT,
    )
    .expect("decrypted call metadata should authorize");
    assert_eq!(authorized_call.tool, "run_tests");

    // ---- Criterion 2: undecryptable privileged events are not executed ----
    // The requester sends a signed exec request into a fresh encrypted room
    // *before* the daemon joins, so the daemon's device is never a recipient of
    // that event's megolm key.
    let utd_room = create_encrypted_room(&bob, "mx-agent E2EE undecryptable").await;
    let utd_room_id = utd_room.room_id().to_owned();
    let utd_content = build_signed_exec_request(
        signing.signing_key(),
        &key_id,
        "inv_e2ee_utd",
        "req_e2ee_utd",
        "e2ee-utd-nonce",
        "2026-06-04T12:00:00Z",
        "2026-06-04T12:05:00Z",
        &exec_options(),
    )
    .expect("sign undecryptable exec request");
    let utd_event_id = utd_room
        .send_raw(timeline::EXEC_REQUEST, utd_content)
        .await
        .expect("send pre-join encrypted exec request")
        .response
        .event_id;

    // Now the daemon joins and syncs; it can fetch the event but must not be
    // able to decrypt it.
    let utd_alice_room = alice
        .join_room_by_id(&utd_room_id)
        .await
        .expect("daemon joins undecryptable room");

    let utd_event = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Ok(event) = utd_alice_room.event(&utd_event_id, None).await {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("daemon should be able to fetch (but not decrypt) the event");

    assert!(
        utd_event.encryption_info().is_none(),
        "privileged event was unexpectedly decryptable; the daemon must not gain \
         keys for events sent before it joined"
    );
    let event_type = utd_event.raw().get_field::<String>("type").ok().flatten();
    assert_eq!(
        event_type.as_deref(),
        Some("m.room.encrypted"),
        "an undecryptable privileged event must remain an opaque m.room.encrypted \
         event — the daemon never sees a {} it could authorize and run",
        timeline::EXEC_REQUEST
    );

    // Stop the sync loops.
    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync task should join")
        .expect("alice sync loop should exit cleanly");
    bob_sync.abort();
}

/// Build a signed, exec-backed task assigned to [`TARGET_AGENT`].
///
/// The action is signed with the shared daemon signing key (`signing`) and
/// addressed to the target agent, so the live scheduler's authorization
/// (trust + signature + replay) admits it before policy and dispatch. `room` is
/// filled in by [`create_task`] from the options.
fn signed_exec_task(
    room_id: &str,
    task_id: &str,
    command: &[&str],
    cwd: &std::path::Path,
    depends_on: Vec<String>,
    signing: &DaemonSigningKey,
    requester: &str,
) -> CreateTaskOptions {
    let unsigned = TaskAction::Exec {
        command: command.iter().map(|s| s.to_string()).collect(),
        cwd: cwd.to_string_lossy().into_owned(),
        env: BTreeMap::new(),
        timeout_ms: Some(60_000),
        stream: false,
        authorization: None,
    };
    let auth = sign_task_action(
        signing.signing_key(),
        signing.key_id(),
        task_id,
        &unsigned,
        requester,
        TARGET_AGENT,
        "2026-06-04T12:00:00Z",
        "2099-01-01T00:00:00Z",
        format!("sched-nonce-{task_id}"),
    )
    .expect("sign task action");
    let action = match unsigned {
        TaskAction::Exec {
            command,
            cwd,
            env,
            timeout_ms,
            stream,
            ..
        } => TaskAction::Exec {
            command,
            cwd,
            env,
            timeout_ms,
            stream,
            authorization: Some(auth),
        },
        _ => unreachable!("exec action"),
    };
    CreateTaskOptions {
        room: room_id.to_string(),
        task_id: Some(task_id.to_string()),
        title: task_id.to_string(),
        description: String::new(),
        state: None,
        assigned_to: TARGET_AGENT.to_string(),
        created_by: Some(requester.to_string()),
        depends_on,
        blocks: Vec::new(),
        action: Some(action),
    }
}

/// Live two-daemon orchestration: the daemon's scheduler loop auto-executes a
/// signed, assigned task DAG over real Matrix room state, honoring dependencies
/// and refusing a policy-denied action (issue #202).
///
/// This drives the real `#[199]` scheduler loop end to end against the live
/// homeserver: Bob (the task creator/requester) publishes three signed
/// `com.mxagent.task.v1` tasks assigned to Alice's agent; Alice runs her real
/// `/sync` loop plus [`run_scheduler_loop`], which reads the tasks, authorizes
/// them (trust + signature + replay), checks deny-by-default policy, claims with
/// `state_rev`, dispatches locally, and finalizes them. The test asserts:
///
/// - the assigned `task-plan` auto-progresses to `succeeded`;
/// - the dependent `task-test` runs only after `task-plan` succeeds; and
/// - the policy-denied `task-denied` is `blocked` and its command never spawns
///   (proven by a sentinel file that must not exist).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_scheduler_executes_signed_task_dag_and_denies() {
    let _serial = enter_single_threaded_section();
    // Capture the scheduler thread's non-sensitive decision logs so a failure is
    // diagnosable from CI output (`--nocapture`).
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");
    let sentinel = cwd.join("denied-ran");
    let approval_sentinel = cwd.join("approval-ran");
    let approval_deny_sentinel = cwd.join("approval-deny-ran");
    // A distinct creator identity whose policy rule requires approval.
    let approver = "@approver:mx-agent.test";

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login should succeed");
    let alice = restore_client(&alice_session)
        .await
        .expect("alice session restore should succeed");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login should succeed");
    let bob = restore_client(&bob_session)
        .await
        .expect("bob session restore should succeed");
    let requester = bob.user_id().expect("bob user id").to_string();

    let room = create_public_room(&bob, "mx-agent live scheduler test").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 4,
        },
    )
    .await
    .expect("register target agent");

    // Trust the shared daemon signing key (both agents publish it) and allow the
    // requester to run `sh` in the work dir. `touch` is deliberately not
    // allowlisted, so `task-denied` is refused before any spawn.
    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]

[rooms."{room}".agents."{approver}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
requires_approval = true
"#,
            room = room_id.as_str(),
            agent = requester,
            approver = approver,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    // Alice's real /sync loop keeps her room state (agents + tasks) fresh for
    // the scheduler, which shares her client.
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };

    // Bob publishes the signed task DAG.
    for opts in [
        signed_exec_task(
            room_id.as_str(),
            "task-plan",
            &["sh", "-c", "exit 0"],
            &cwd,
            Vec::new(),
            &signing,
            &requester,
        ),
        signed_exec_task(
            room_id.as_str(),
            "task-test",
            &["sh", "-c", "exit 0"],
            &cwd,
            vec!["task-plan".to_string()],
            &signing,
            &requester,
        ),
        signed_exec_task(
            room_id.as_str(),
            "task-denied",
            &["touch", sentinel.to_string_lossy().as_ref()],
            &cwd,
            Vec::new(),
            &signing,
            &requester,
        ),
        // Policy-allowed but `requires_approval`: the live scheduler holds it
        // (fail closed) until an operator approves it over IPC, then it runs.
        signed_exec_task(
            room_id.as_str(),
            "task-approval",
            &[
                "sh",
                "-c",
                &format!("touch {}", approval_sentinel.to_string_lossy()),
            ],
            &cwd,
            Vec::new(),
            &signing,
            approver,
        ),
        // Also `requires_approval`: this one is denied over IPC, so it must reach
        // `blocked` and its command must never spawn.
        signed_exec_task(
            room_id.as_str(),
            "task-approval-deny",
            &[
                "sh",
                "-c",
                &format!("touch {}", approval_deny_sentinel.to_string_lossy()),
            ],
            &cwd,
            Vec::new(),
            &signing,
            approver,
        ),
    ] {
        create_task(&bob, &opts)
            .await
            .unwrap_or_else(|e| panic!("create {}: {e}", opts.task_id.as_deref().unwrap_or("")));
    }

    // Run the real daemon scheduler loop on its own thread (it owns a
    // current-thread runtime and shares Alice's client), driving tasks from the
    // live room state.
    let scheduler = {
        let alice = alice.clone();
        let running = running.clone();
        std::thread::spawn(move || {
            run_scheduler_loop(
                alice,
                ExecSubscriberRegistry::new(),
                TaskDispatchMode::Local,
                running,
                Duration::from_secs(1),
            );
        })
    };

    // Poll the room's task state (via Bob) until the DAG settles or we time out.
    let list_opts = ListTasksOptions {
        room: room_id.to_string(),
        state: None,
        assigned_to: None,
    };
    let mut final_states: BTreeMap<String, String> = BTreeMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(150);
    loop {
        if let Ok(tasks) = list_tasks(&bob, &list_opts).await {
            final_states = tasks.into_iter().map(|t| (t.task_id, t.state)).collect();
            let plan = final_states.get("task-plan").map(String::as_str);
            let test = final_states.get("task-test").map(String::as_str);
            let denied = final_states.get("task-denied").map(String::as_str);
            if plan == Some("succeeded") && test == Some("succeeded") && denied == Some("blocked") {
                break;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Fail-closed before any decision: both approval-required tasks are held
    // (still `pending`, never `succeeded`) and their commands have not spawned.
    assert_ne!(
        final_states.get("task-approval").map(String::as_str),
        Some("succeeded"),
        "approval-required task must be held until approved; states: {final_states:?}"
    );
    assert_ne!(
        final_states.get("task-approval-deny").map(String::as_str),
        Some("succeeded"),
        "approval-required task must be held until decided; states: {final_states:?}"
    );
    assert!(
        !approval_sentinel.exists() && !approval_deny_sentinel.exists(),
        "approval-required commands must not spawn before a decision"
    );

    // The scheduler enqueues a pending approval per held task into the local
    // queue (so `mx-agent approval approve/deny` over IPC can resolve it). Wait
    // for both to appear before deciding.
    let approve_id = "approval:task-approval";
    let deny_id = "approval:task-approval-deny";
    let queue_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let pending = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
        let ids: std::collections::BTreeSet<&str> =
            pending.iter().map(|p| p.request_id()).collect();
        if ids.contains(approve_id) && ids.contains(deny_id) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < queue_deadline,
            "scheduler should enqueue pending approvals; queued: {ids:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Decide over the daemon's session exactly as the `approval.decide` IPC path
    // does: approve one held task and deny the other. The decision is published
    // into the room, where the live scheduler resolves it on its next pass.
    decide_approval_for_session(
        &alice_session,
        &paths,
        approve_id,
        DECISION_APPROVED,
        alice_id.as_str(),
    )
    .await
    .expect("approve the held task");
    decide_approval_for_session(
        &alice_session,
        &paths,
        deny_id,
        DECISION_DENIED,
        alice_id.as_str(),
    )
    .await
    .expect("deny the held task");

    // After the decisions, the approved task auto-progresses to `succeeded` and
    // the denied task is finalized `blocked`.
    let decided_deadline = tokio::time::Instant::now() + Duration::from_secs(150);
    loop {
        if let Ok(tasks) = list_tasks(&bob, &list_opts).await {
            final_states = tasks.into_iter().map(|t| (t.task_id, t.state)).collect();
            let approved = final_states.get("task-approval").map(String::as_str);
            let denied = final_states.get("task-approval-deny").map(String::as_str);
            if approved == Some("succeeded") && denied == Some("blocked") {
                break;
            }
        }
        if tokio::time::Instant::now() >= decided_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Dump the final task state + result for each task to aid CI debugging.
    if let Ok(tasks) = list_tasks(&bob, &list_opts).await {
        for t in &tasks {
            eprintln!(
                "DIAG task={} state={} result={}",
                t.task_id,
                t.state,
                t.result
                    .as_ref()
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "null".to_string())
            );
        }
    }

    // Stop the scheduler and sync loops before tearing down the environment.
    running.store(false, Ordering::SeqCst);
    scheduler.join().expect("scheduler thread joins");
    alice_sync
        .await
        .expect("alice sync task joins")
        .expect("alice sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");

    assert_eq!(
        final_states.get("task-plan").map(String::as_str),
        Some("succeeded"),
        "assigned task should auto-progress to succeeded; states: {final_states:?}"
    );
    assert_eq!(
        final_states.get("task-test").map(String::as_str),
        Some("succeeded"),
        "dependent task should run only after its dependency succeeds; states: {final_states:?}"
    );
    assert_eq!(
        final_states.get("task-denied").map(String::as_str),
        Some("blocked"),
        "policy-denied task must be blocked, not executed; states: {final_states:?}"
    );
    assert!(
        !sentinel.exists(),
        "policy-denied task's command must never spawn (sentinel must not exist)"
    );
    // Approve→execute: the approved task ran to success and its command spawned.
    assert_eq!(
        final_states.get("task-approval").map(String::as_str),
        Some("succeeded"),
        "approved task must auto-progress to succeeded; states: {final_states:?}"
    );
    assert!(
        approval_sentinel.exists(),
        "approved task's command must spawn after approval"
    );
    // Deny→blocked: the denied task is blocked and its command never spawned.
    assert_eq!(
        final_states.get("task-approval-deny").map(String::as_str),
        Some("blocked"),
        "denied task must be blocked, not executed; states: {final_states:?}"
    );
    assert!(
        !approval_deny_sentinel.exists(),
        "denied task's command must never spawn"
    );
}

/// Live proof of the production daemon-side task-action signing path (issue #302).
///
/// Verifies end-to-end that a task created through the production
/// [`create_task_for_session`] IPC entry point with an unsigned `Exec` action
/// is daemon-signed at authoring time, then claimed, dispatched, and executed
/// by the live scheduler — **no** manual [`sign_task_action`] call anywhere in
/// the user flow.
///
/// Two tasks are published in the same scheduler run to prove both directions:
///
/// - `task-302-prod`: created via [`create_task_for_session`] with
///   `authorization: None`; the daemon signs it with its own Ed25519 key. The
///   live scheduler finds it correctly signed and runs it to `succeeded`.
/// - `task-302-untrusted`: pre-signed with a **throwaway key that is not in
///   the trust store**, then published via [`create_task`] directly (so the
///   authoring path is not invoked — the action already carries an
///   authorization). The scheduler rejects it as `untrusted_key` and
///   finalizes it `blocked`, proving that daemon-side signing at authoring
///   time does not weaken executing-side enforcement.
///
/// The existing [`signed_exec_task`] helper (manual sign before create) is
/// the positive control and is preserved in [`live_scheduler_executes_signed_task_dag_and_denies`].
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_production_task_create_signs_and_executes() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login should succeed");
    let alice = restore_client(&alice_session)
        .await
        .expect("alice session restore should succeed");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login should succeed");
    let bob = restore_client(&bob_session)
        .await
        .expect("bob session restore should succeed");

    // Alice creates the room (PL 100 as creator) so she can write state events
    // for agent registration, task creation, and scheduler updates without a
    // separate power-level grant. Bob joins only to list task states from
    // outside the scheduler thread.
    let room = create_public_room(&alice, "mx-agent 302 production-sign test").await;
    let room_id = room.room_id().to_owned();
    bob.join_room_by_id(&room_id).await.expect("bob joins room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    let bob_id = bob.user_id().expect("bob user id").to_owned();
    wait_for_joined_member(&room, &bob_id).await;

    // Register TARGET_AGENT owned by Alice. The agent-state entry includes
    // Alice's signing public key, which the scheduler uses to resolve the
    // verifying key when it checks the signature.
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it-302".to_string(),
            max_invocations: 2,
        },
    )
    .await
    .expect("register target agent");

    // Daemon signing key — the same key `create_task_for_session` and
    // `register_agent` both loaded from `ENV_DATA_DIR` (via
    // `SessionPaths::resolve()`). This is the key the trust store must trust
    // for the scheduler to admit the production-path task.
    let signing = load_or_create_signing_key(&paths).expect("signing key");

    // Build a second, throwaway signing key that will NOT be added to the trust
    // store. Used to produce the negative-case pre-signed action.
    let untrusted_dir = data_dir.join("untrusted");
    paths_in(untrusted_dir.clone())
        .ensure_data_dir()
        .expect("create untrusted dir");
    let untrusted_signing =
        load_or_create_signing_key(&paths_in(untrusted_dir)).expect("untrusted signing key");
    assert_ne!(
        signing.key_id(),
        untrusted_signing.key_id(),
        "the two signing identities must be distinct for this test to be meaningful"
    );

    // Trust only the daemon's own key. `create_task_for_session` will sign
    // the production task with this key (addressed to TARGET_AGENT). The
    // untrusted key is deliberately omitted so the scheduler blocks that task.
    let alice_id_str = alice_id.to_string();
    let mut trust = TrustStore::default();
    trust.approve(
        alice_id_str.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");

    // Policy: allow the task creator (Alice's Matrix user id = `created_by`)
    // to run "sh" in the work directory. Deny-by-default for everything else.
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{alice_id}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
"#,
            room = room_id.as_str(),
            alice_id = alice_id_str,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    // ── Production-path task: no pre-signed authorization ──
    //
    // This is the scenario issue #302 targeted: a user runs
    // `mx-agent task create --exec -- sh -c 'exit 0'`. The CLI emits
    // `authorization: None`; the daemon signs daemon-side in
    // `create_task_for_session`. No manual `sign_task_action` call here.
    let prod_task_id = "task-302-prod";
    create_task_for_session(
        &alice_session,
        &CreateTaskOptions {
            room: room_id.to_string(),
            task_id: Some(prod_task_id.to_string()),
            title: "production-path exec task (issue #302)".to_string(),
            description: String::new(),
            state: None,
            assigned_to: TARGET_AGENT.to_string(),
            created_by: Some(alice_id_str.clone()),
            depends_on: Vec::new(),
            blocks: Vec::new(),
            action: Some(TaskAction::Exec {
                command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
                cwd: cwd.to_string_lossy().into_owned(),
                env: BTreeMap::new(),
                timeout_ms: Some(60_000),
                stream: false,
                authorization: None,
            }),
        },
    )
    .await
    .expect("production-path create_task_for_session must succeed");

    // Verify the daemon attached an authorization at authoring time, without
    // any manual sign_task_action call. This is the direct proof of #302.
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice syncs to read task state");
    {
        let tasks = list_tasks(
            &alice,
            &ListTasksOptions {
                room: room_id.to_string(),
                state: None,
                assigned_to: None,
            },
        )
        .await
        .expect("alice lists tasks after sync");
        let prod = tasks
            .iter()
            .find(|t| t.task_id == prod_task_id)
            .expect("production task must exist");
        assert!(
            prod.action
                .as_ref()
                .and_then(|a| a.authorization())
                .is_some(),
            "create_task_for_session must have daemon-signed the action (no manual \
             sign_task_action call); issue #302 — task: {:?}",
            prod
        );
        // The authorization must be addressed to TARGET_AGENT.
        let auth = prod
            .action
            .as_ref()
            .and_then(|a| a.authorization())
            .expect("authorization present");
        assert_eq!(
            auth.target_agent, TARGET_AGENT,
            "daemon-authored authorization must target the executing agent"
        );
    }

    // ── Negative case: pre-signed by an untrusted key ──
    //
    // The action already carries an authorization from the throwaway key, so
    // `create_task_for_session` would leave it untouched (the daemon never
    // overwrites an existing signature). Using `create_task` directly makes
    // the test intent explicit: we want the scheduler to see this key and
    // reject it as `untrusted_key`.
    let untrusted_task_id = "task-302-untrusted";
    let unsigned_exec = TaskAction::Exec {
        command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
        cwd: cwd.to_string_lossy().into_owned(),
        env: BTreeMap::new(),
        timeout_ms: Some(60_000),
        stream: false,
        authorization: None,
    };
    let untrusted_auth = sign_task_action(
        untrusted_signing.signing_key(),
        untrusted_signing.key_id(),
        untrusted_task_id,
        &unsigned_exec,
        &alice_id_str,
        TARGET_AGENT,
        "2026-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        format!("untrusted-nonce-{untrusted_task_id}"),
    )
    .expect("sign with untrusted key");
    create_task(
        &alice,
        &CreateTaskOptions {
            room: room_id.to_string(),
            task_id: Some(untrusted_task_id.to_string()),
            title: "untrusted-key task (negative case — must stay blocked)".to_string(),
            description: String::new(),
            state: None,
            assigned_to: TARGET_AGENT.to_string(),
            created_by: Some(alice_id_str.clone()),
            depends_on: Vec::new(),
            blocks: Vec::new(),
            action: Some(unsigned_exec.with_authorization(untrusted_auth)),
        },
    )
    .await
    .expect("publish untrusted-key task");

    // Alice's /sync loop keeps her room state fresh for the scheduler.
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };

    // Run the real scheduler loop: admits the production-path task (trusted,
    // signed, policy-allowed) and blocks the untrusted-key task.
    let scheduler = {
        let alice = alice.clone();
        let running = running.clone();
        std::thread::spawn(move || {
            run_scheduler_loop(
                alice,
                ExecSubscriberRegistry::new(),
                TaskDispatchMode::Local,
                running,
                Duration::from_secs(1),
            );
        })
    };

    // Poll until both tasks reach a terminal state or the deadline expires.
    let list_opts = ListTasksOptions {
        room: room_id.to_string(),
        state: None,
        assigned_to: None,
    };
    let mut final_states: BTreeMap<String, String> = BTreeMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        if let Ok(tasks) = list_tasks(&bob, &list_opts).await {
            final_states = tasks.into_iter().map(|t| (t.task_id, t.state)).collect();
            let prod = final_states.get(prod_task_id).map(String::as_str);
            let untrusted = final_states.get(untrusted_task_id).map(String::as_str);
            let prod_terminal =
                matches!(prod, Some("succeeded") | Some("blocked") | Some("failed"));
            let untrusted_terminal = matches!(
                untrusted,
                Some("succeeded") | Some("blocked") | Some("failed")
            );
            if prod_terminal && untrusted_terminal {
                break;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Diagnostic dump for CI output on failure.
    if let Ok(tasks) = list_tasks(&bob, &list_opts).await {
        for t in &tasks {
            eprintln!(
                "DIAG task={} state={} result={}",
                t.task_id,
                t.state,
                t.result
                    .as_ref()
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "null".to_string())
            );
        }
    }

    running.store(false, Ordering::SeqCst);
    scheduler.join().expect("scheduler thread should join");
    alice_sync
        .await
        .expect("alice sync task should join")
        .expect("alice sync loop should exit cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");

    // Production-path task must execute without any manual sign_task_action
    // call — this is the end-to-end acceptance criterion for issue #302.
    assert_eq!(
        final_states.get(prod_task_id).map(String::as_str),
        Some("succeeded"),
        "production-path task (daemon-signed via create_task_for_session, \
         no manual sign_task_action) must execute; states: {final_states:?}"
    );

    // Executing-side enforcement must be intact: the untrusted-key task is
    // blocked even though it carries a signature, proving authoring-side
    // signing did not weaken execution.
    assert_eq!(
        final_states.get(untrusted_task_id).map(String::as_str),
        Some("blocked"),
        "task pre-signed by an untrusted key must be blocked (untrusted_key); \
         authoring-side signing must not weaken executing-side enforcement; \
         states: {final_states:?}"
    );
}

/// Live task cancel drives the linked remote invocation (issue #239).
///
/// This exercises the unified task↔remote-invocation id end to end without the
/// scheduler, so it is deterministic: Bob starts a long-running signed remote
/// `exec` against Alice under a *preset* invocation id (the new
/// [`ExecStartParams::invocation_id`]), and a `com.mxagent.task.v1` task is
/// published carrying that *same* id as its `invocation_id`. Once the remote
/// invocation is live (`running`), Bob issues `cancel_task`, which:
///
/// - signs a `com.mxagent.exec.cancel.v1` so Alice (the target) verifies Bob's
///   ownership, terminates the process group, and confirms `exec.cancelled`;
/// - republishes the invocation state `cancelled`; and
/// - finalizes the owning task `cancelled` by the unified id.
///
/// The test asserts the task's `invocation_id` equals the live invocation's id
/// (unification), the task is finalized `cancelled`, and the invocation reaches
/// `cancelled`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_task_cancel_drives_remote_invocation() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login should succeed");
    let alice = restore_client(&alice_session)
        .await
        .expect("alice session restore should succeed");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login should succeed");
    let bob = restore_client(&bob_session)
        .await
        .expect("bob session restore should succeed");
    let requester_agent = bob.user_id().expect("bob user id").to_string();

    let room = create_public_room(&bob, "mx-agent live task cancel test").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester_agent.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register target agent");

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
"#,
            room = room_id.as_str(),
            agent = requester_agent,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    let subscribers = ExecSubscriberRegistry::new();
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &alice,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };
    let bob_sync_paths = paths_in(data_dir.join("bob-sync"));
    bob_sync_paths
        .ensure_data_dir()
        .expect("create bob sync dir");
    let bob_sync = {
        let bob = bob.clone();
        let paths = bob_sync_paths.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &bob,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };

    // The daemon-global session start_exec_matrix reads is Bob's.
    save_session(&paths, &bob_session).expect("save requester session");

    // The unified id: the task records it and the remote exec runs under it.
    let invocation_id = mx_agent_protocol::id::generate_invocation_id();
    let task_id = "task-cancel";

    // Publish the task and link it to the unified invocation id in `executing`.
    create_task(
        &bob,
        &CreateTaskOptions {
            room: room_id.to_string(),
            task_id: Some(task_id.to_string()),
            title: task_id.to_string(),
            description: String::new(),
            state: None,
            assigned_to: TARGET_AGENT.to_string(),
            created_by: Some(requester_agent.clone()),
            depends_on: Vec::new(),
            blocks: Vec::new(),
            action: None,
        },
    )
    .await
    .expect("create task");
    mx_agent_daemon::update_task(
        &bob,
        &mx_agent_daemon::UpdateTaskOptions {
            room: room_id.to_string(),
            task_id: task_id.to_string(),
            state: Some("executing".to_string()),
            invocation_id: Some(invocation_id.clone()),
            ..Default::default()
        },
    )
    .await
    .expect("link task to invocation id");

    // Start a long-running remote exec under the preset (unified) invocation id.
    let exec = {
        let subscribers = subscribers.clone();
        let room_id = room_id.to_string();
        let invocation_id = invocation_id.clone();
        tokio::spawn(async move {
            start_exec_matrix(
                &ExecStartParams {
                    room: Some(room_id),
                    agent: Some(TARGET_AGENT.to_string()),
                    command: vec!["sh".to_string(), "-c".to_string(), "sleep 120".to_string()],
                    cwd: Some(cwd.clone()),
                    stdin: None,
                    stream: true,
                    pty: false,
                    task: Some(task_id.to_string()),
                    strict_stream: false,
                    env: Default::default(),
                    timeout_ms: None,
                    invocation_id: Some(invocation_id),
                },
                &subscribers,
            )
            .await
        })
    };

    // Wait for the remote invocation to go live under the unified id.
    let live_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(Some(inv)) = get_invocation(&bob, room_id.as_str(), &invocation_id).await {
            if inv.state == "running" || inv.state == "accepted" {
                break;
            }
        }
        assert!(
            tokio::time::Instant::now() < live_deadline,
            "remote invocation {invocation_id} should go live under the unified id"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Cancel the task: drive the linked invocation to cancelled and finalize the
    // task cancelled by the unified id.
    let cancelled_task = cancel_task_for_session(
        &bob_session,
        signing.signing_key(),
        &signing.key_id(),
        room_id.as_str(),
        task_id,
        "test cancel",
    )
    .await
    .expect("cancel task");
    assert_eq!(
        cancelled_task.invocation_id.as_deref(),
        Some(invocation_id.as_str()),
        "the task records the unified invocation id"
    );
    assert_eq!(
        cancelled_task.state, "cancelled",
        "task cancel finalizes the owning task cancelled"
    );

    // The linked remote invocation reaches `cancelled`.
    let cancel_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut invocation_state = String::new();
    loop {
        if let Ok(Some(inv)) = get_invocation(&bob, room_id.as_str(), &invocation_id).await {
            invocation_state = inv.state.clone();
            if inv.state == "cancelled" {
                break;
            }
        }
        if tokio::time::Instant::now() >= cancel_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        invocation_state, "cancelled",
        "task cancel must drive the linked remote invocation to cancelled"
    );

    // The remote exec returns once its process group is killed.
    let _ = exec.await.expect("remote exec task joins");

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync task joins")
        .expect("alice sync exits cleanly");
    bob_sync.abort();
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");
}

/// App-level agent id daemon A (Alice) advertises in the discovery test.
const ALICE_AGENT: &str = "claude-local";
/// App-level agent id daemon B (Bob) advertises in the discovery test.
const BOB_AGENT: &str = "developer-pi";

/// Poll [`list_agents`] until every id in `expected` is present (bounded), then
/// return the discovered agents keyed by `agent_id`.
///
/// `list_agents` re-syncs the client on each call, so retrying it also drives
/// the daemon's view of room state forward without a background sync loop —
/// deterministic discovery with a bounded retry instead of a fixed sleep.
async fn discover_agents(
    client: &Client,
    room: &str,
    expected: &[&str],
) -> BTreeMap<String, AgentState> {
    let opts = ListAgentsOptions {
        room: room.to_string(),
        capabilities: Vec::new(),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(agents) = list_agents(client, &opts).await {
            let map: BTreeMap<String, AgentState> = agents
                .into_iter()
                .map(|a| (a.agent_id.clone(), a))
                .collect();
            if expected.iter().all(|id| map.contains_key(*id)) {
                return map;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "agents {expected:?} were not all discovered before the timeout"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Pin the stable `--json` shape of a discovered agent.
///
/// `mx-agent agent list --json` and `agent show --json` serialize [`AgentState`]
/// verbatim (`crates/mx-agent-cli/src/cli.rs`), so a field rename or drop here
/// would silently break automation consuming that JSON. Assert the documented
/// keys exist with the right value types, including the nested `workspace` and
/// `load` objects, and that `signing_key_id` round-trips the publishing daemon's
/// key.
fn assert_stable_agent_json(state: &AgentState, expected_key_id: &str) {
    let v = serde_json::to_value(state).expect("agent state serializes to json");
    let obj = v.as_object().expect("agent --json is an object");
    for key in [
        "agent_id",
        "kind",
        "matrix_user_id",
        "device_id",
        "signing_key_id",
        "signing_public_key",
        "status",
        "capabilities",
        "tools",
        "workspace",
        "load",
        "last_seen_ts",
        "state_rev",
    ] {
        assert!(
            obj.contains_key(key),
            "agent --json missing stable key `{key}`: {v}"
        );
    }
    assert_eq!(
        obj["signing_key_id"],
        json!(expected_key_id),
        "discovered signing_key_id must round-trip the publishing daemon's key"
    );
    assert!(
        obj["capabilities"].is_array(),
        "capabilities must be a JSON array"
    );
    assert!(obj["tools"].is_array(), "tools must be a JSON array");
    assert!(
        obj["last_seen_ts"].is_u64(),
        "last_seen_ts must be a JSON number"
    );
    assert!(obj["state_rev"].is_u64(), "state_rev must be a JSON number");

    let ws = obj["workspace"]
        .as_object()
        .expect("workspace must be a JSON object");
    for key in ["cwd", "project_id", "git_commit"] {
        assert!(
            ws.contains_key(key),
            "workspace --json missing `{key}`: {v}"
        );
    }
    let load = obj["load"].as_object().expect("load must be a JSON object");
    for key in ["running_invocations", "max_invocations"] {
        assert!(load.contains_key(key), "load --json missing `{key}`: {v}");
    }
}

/// Pin the stable `--json` shape of the liveness-enriched envelope (issue #250).
///
/// `mx-agent agent list --json` and `agent show --json` now return
/// `AgentListing` (`{ "agent": AgentState, "liveness": "active"|"stale"|"offline" }`)
/// rather than bare `AgentState`. Automation must read fields under `.[].agent`
/// rather than at the top level. Assert the documented envelope shape including
/// the lowercase `liveness` string and nested `agent` object with all stable keys.
fn assert_stable_agent_listing_json(state: &AgentState, liveness: Liveness, expected_key_id: &str) {
    let listing = AgentListing {
        agent: state.clone(),
        liveness,
    };
    let v = serde_json::to_value(&listing).expect("AgentListing serializes to json");
    let obj = v.as_object().expect("AgentListing --json is an object");

    // Envelope-level keys must be exactly "agent" and "liveness".
    assert!(
        obj.contains_key("liveness"),
        "AgentListing --json must have 'liveness' field: {v}"
    );
    assert!(
        obj.contains_key("agent"),
        "AgentListing --json must have 'agent' field: {v}"
    );
    let liveness_str = obj["liveness"]
        .as_str()
        .expect("liveness field must be a string");
    assert!(
        ["active", "stale", "offline"].contains(&liveness_str),
        "liveness must be 'active', 'stale', or 'offline': got {liveness_str:?}"
    );
    assert!(
        obj.get("agent_id").is_none(),
        "agent_id must not appear at the envelope top level; it must live under 'agent'"
    );

    // The inner AgentState must carry all documented keys under "agent".
    let agent_obj = obj["agent"]
        .as_object()
        .expect("'agent' must be a JSON object");
    for key in [
        "agent_id",
        "kind",
        "matrix_user_id",
        "device_id",
        "signing_key_id",
        "signing_public_key",
        "status",
        "capabilities",
        "tools",
        "workspace",
        "load",
        "last_seen_ts",
        "state_rev",
    ] {
        assert!(
            agent_obj.contains_key(key),
            "AgentListing --json 'agent' must have '{key}' field: {v}"
        );
    }
    assert_eq!(
        agent_obj["signing_key_id"],
        json!(expected_key_id),
        "discovered signing_key_id must round-trip the publishing daemon's key"
    );
    assert!(
        agent_obj["last_seen_ts"].is_u64(),
        "last_seen_ts must be a JSON number"
    );
    assert!(
        agent_obj["state_rev"].is_u64(),
        "state_rev must be a JSON number"
    );
}

/// Two-daemon agent discovery + liveness coverage (issue #227).
///
/// Two independent daemons — two Matrix users, each with its **own** data dir and
/// therefore its own Ed25519 signing identity — join one workspace room and each
/// register a `com.mxagent.agent.v1` agent. The test asserts the two contracts
/// the discovery/liveness feature promises but that no focused test pinned
/// before:
///
/// 1. **Discovery.** Daemon A sees daemon B's published agent state (and vice
///    versa) over `/sync`, carrying B's advertised kind, capabilities, tools, and
///    its distinct `signing_key_id`/public key. `show_agent` agrees with
///    `list_agents`.
/// 2. **Heartbeat-driven liveness.** B emits a real `com.mxagent.heartbeat.v1`
///    that refreshes its durable state; A observes the advanced
///    `last_seen_ts`/`state_rev`. Given that durable `last_seen_ts`, the
///    `LivenessConfig` thresholds drive the documented Active → Stale → Offline
///    transition (architecture §9.1).
///
/// Liveness is evaluated against an **injected** `now` clock and injected
/// thresholds rather than wall-clock sleeps, so the state-machine assertion is
/// deterministic and cannot flake the way time-based waits did in #221. Finally
/// it pins the `--json` agent output shape automation depends on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn two_daemons_discover_each_other_and_compute_liveness() {
    let _serial = enter_single_threaded_section();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    // Each daemon gets its own data dir so it has a distinct signing identity,
    // exactly like two independent installs. `register_agent` loads its signing
    // key from `MX_AGENT_DATA_DIR` (via `SessionPaths::resolve`), so point the env
    // var at the right daemon's dir around each registration call. The `#[ignore]`
    // suite runs single-threaded (`--test-threads=1`), so toggling this
    // process-global env var here does not race other tests.
    let base = throwaway_data_dir();
    let alice_dir = base.join("alice");
    let bob_dir = base.join("bob");
    paths_in(alice_dir.clone())
        .ensure_data_dir()
        .expect("create alice data dir");
    paths_in(bob_dir.clone())
        .ensure_data_dir()
        .expect("create bob data dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login should succeed");
    let alice = restore_client(&alice_session)
        .await
        .expect("alice session restore should succeed");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login should succeed");
    let bob = restore_client(&bob_session)
        .await
        .expect("bob session restore should succeed");

    // Bob creates the shared workspace room; Alice (the second daemon) joins.
    let room = create_public_room(&bob, "mx-agent discovery + liveness test").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;

    // Both daemons must be able to publish `com.mxagent.agent.v1` state. Bob (room
    // creator, PL 100) grants Alice PL 50, the `state_default` for agent state.
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    // Register Bob's agent under Bob's data dir/signing key.
    std::env::set_var(ENV_DATA_DIR, &bob_dir);
    let bob_signing =
        load_or_create_signing_key(&paths_in(bob_dir.clone())).expect("bob signing key");
    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(BOB_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec![
                "shell".to_string(),
                "edit".to_string(),
                "test".to_string(),
                "repo:node".to_string(),
            ],
            tools: vec!["run_tests@1.0.0".to_string(), "lint@1.0.0".to_string()],
            cwd: "/home/me/code/project".to_string(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 4,
        },
    )
    .await
    .expect("register bob agent");

    // Register Alice's agent under Alice's data dir/signing key.
    std::env::set_var(ENV_DATA_DIR, &alice_dir);
    let alice_signing =
        load_or_create_signing_key(&paths_in(alice_dir.clone())).expect("alice signing key");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(ALICE_AGENT.to_string()),
            kind: "claude-code".to_string(),
            capabilities: vec!["plan".to_string(), "review".to_string()],
            tools: vec![],
            cwd: "/home/me/code/project".to_string(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register alice agent");
    std::env::remove_var(ENV_DATA_DIR);

    // Sanity: the two daemons really do have distinct signing identities.
    assert_ne!(
        bob_signing.key_id(),
        alice_signing.key_id(),
        "two independent daemons must have distinct signing keys"
    );

    // ---- Criterion: each daemon discovers BOTH agents over /sync. ----
    let by_alice = discover_agents(&alice, room_id.as_str(), &[ALICE_AGENT, BOB_AGENT]).await;
    let by_bob = discover_agents(&bob, room_id.as_str(), &[ALICE_AGENT, BOB_AGENT]).await;

    // Daemon A (Alice) sees daemon B (Bob) with B's advertised metadata.
    let bob_seen_by_alice = by_alice.get(BOB_AGENT).expect("alice discovers bob");
    assert_eq!(bob_seen_by_alice.kind, "pi");
    assert_eq!(
        bob_seen_by_alice.capabilities,
        vec!["shell", "edit", "test", "repo:node"]
    );
    assert_eq!(
        bob_seen_by_alice.tools,
        vec!["run_tests@1.0.0", "lint@1.0.0"]
    );
    assert_eq!(
        bob_seen_by_alice.signing_key_id,
        bob_signing.key_id(),
        "discovered agent must carry the publishing daemon's signing key id"
    );
    assert!(
        bob_seen_by_alice.signing_public_key.is_some(),
        "discovered agent must advertise its public signing key"
    );

    // Daemon B (Bob) sees daemon A (Alice) with A's advertised metadata.
    let alice_seen_by_bob = by_bob.get(ALICE_AGENT).expect("bob discovers alice");
    assert_eq!(alice_seen_by_bob.kind, "claude-code");
    assert_eq!(alice_seen_by_bob.capabilities, vec!["plan", "review"]);
    assert!(
        alice_seen_by_bob.tools.is_empty(),
        "alice advertised no tools"
    );
    assert_eq!(alice_seen_by_bob.signing_key_id, alice_signing.key_id());

    // The two discovered signing identities differ, confirming per-daemon keys
    // survive the publish → discover round trip.
    assert_ne!(
        bob_seen_by_alice.signing_key_id, alice_seen_by_bob.signing_key_id,
        "discovery must preserve each daemon's distinct signing identity"
    );

    // Single-agent discovery (`show_agent`) agrees with the list view.
    let bob_shown = show_agent(&alice, room_id.as_str(), BOB_AGENT)
        .await
        .expect("show bob")
        .expect("bob is registered");
    assert_eq!(
        &bob_shown, bob_seen_by_alice,
        "show_agent and list_agents must report the same state"
    );

    // ---- Criterion: a real heartbeat refreshes B's durable liveness state. ----
    // Force a state refresh (zero refresh interval) so the timeline heartbeat also
    // advances the durable `last_seen_ts`/`state_rev` A reads.
    let initial_last_seen = bob_seen_by_alice.last_seen_ts;
    let initial_state_rev = bob_seen_by_alice.state_rev;
    assert!(
        initial_last_seen > 0,
        "registration must stamp a real last_seen_ts"
    );
    let hb_cfg = HeartbeatConfig {
        state_refresh: Duration::ZERO,
        ..HeartbeatConfig::default()
    };
    let refreshed = emit_heartbeat(&room, BOB_AGENT, "active", &hb_cfg, 0)
        .await
        .expect("emit heartbeat");
    assert!(
        refreshed,
        "a forced state-refresh heartbeat must rewrite the durable agent state"
    );

    // A re-discovers B and observes the heartbeat-advanced durable state. The
    // refresh may race the heartbeat's `/sync` echo, so poll with a bounded
    // deadline rather than a fixed sleep.
    let hb_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let bob_after_hb = loop {
        let map = discover_agents(&alice, room_id.as_str(), &[BOB_AGENT]).await;
        let b = map.get(BOB_AGENT).expect("alice still sees bob");
        if b.state_rev > initial_state_rev {
            break b.clone();
        }
        assert!(
            tokio::time::Instant::now() < hb_deadline,
            "heartbeat-refreshed state (state_rev > {initial_state_rev}) was not observed in time"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert!(
        bob_after_hb.last_seen_ts >= initial_last_seen,
        "heartbeat must not move last_seen_ts backwards"
    );
    assert!(
        bob_after_hb.state_rev > initial_state_rev,
        "heartbeat state refresh must advance state_rev"
    );

    // ---- Criterion: liveness transitions Active → Stale → Offline. ----
    // Inject thresholds and the `now` clock — no sleeps — so this is deterministic
    // (the flakiness class tracked in #221). "Heartbeats lapse" is modeled by
    // evaluating liveness at increasing `now` past B's last heartbeat.
    let cfg = LivenessConfig {
        stale_after: Duration::from_secs(10),
        offline_after: Duration::from_secs(30),
    };
    let last_seen = bob_after_hb.last_seen_ts;
    assert_eq!(
        cfg.liveness_of(&bob_after_hb, last_seen + 1_000),
        Liveness::Active,
        "within the stale window the agent is active"
    );
    assert_eq!(
        cfg.liveness_of(
            &bob_after_hb,
            last_seen + cfg.stale_after.as_millis() as u64
        ),
        Liveness::Stale,
        "past the stale threshold the agent is stale"
    );
    assert_eq!(
        cfg.liveness_of(
            &bob_after_hb,
            last_seen + cfg.offline_after.as_millis() as u64
        ),
        Liveness::Offline,
        "past the offline threshold the agent is offline"
    );

    // ---- Criterion: read_latest_heartbeats returns the emitted heartbeat. ----
    // This is the first end-to-end coverage of `read_latest_heartbeats` against a
    // real Matrix homeserver timeline (issue #250). The heartbeat was emitted via
    // `emit_heartbeat`, which sends a `com.mxagent.heartbeat.v1` timeline event.
    // `read_latest_heartbeats` paginates `/messages` backward (up to
    // `MAX_HEARTBEAT_SCAN_EVENTS`) and sender-pins each heartbeat to the registered
    // agent (issue #312), so it is passed Bob's agent state and must find Bob's own
    // heartbeat (sender == Bob's `matrix_user_id`).
    let latest = read_latest_heartbeats(
        &room,
        std::slice::from_ref(&bob_after_hb),
        HEARTBEAT_SCAN_LIMIT,
    )
    .await
    .expect("read_latest_heartbeats must succeed against the live homeserver");
    assert!(
        latest.contains_key(BOB_AGENT),
        "emitted heartbeat must appear in the timeline scan for agent {BOB_AGENT}: found {:?}",
        latest.keys().collect::<Vec<_>>()
    );
    let hb = &latest[BOB_AGENT];
    assert_eq!(
        hb.agent_id, BOB_AGENT,
        "heartbeat agent_id must match the emitting agent"
    );
    assert!(
        hb.ts >= initial_last_seen,
        "heartbeat ts ({}) must not predate the initial last_seen_ts ({})",
        hb.ts,
        initial_last_seen
    );

    // ---- Criterion: liveness_combined lifts Offline to Active via timeline. ----
    // With short injected thresholds and a `now` far past the durable
    // `last_seen_ts`, durable-only liveness is Offline. The timeline heartbeat
    // ts (just emitted) makes the combined verdict Active — the core correctness
    // property of issue #250: a healthy agent emitting 30s heartbeats stays
    // Active between the slower 300s durable-state refreshes.
    let tight_cfg = LivenessConfig {
        stale_after: Duration::from_secs(1),
        offline_after: Duration::from_secs(5),
    };
    // Simulate durable state being 10 minutes old.
    let far_future = bob_after_hb.last_seen_ts + 600_000;
    assert_eq!(
        tight_cfg.liveness_of(&bob_after_hb, far_future),
        Liveness::Offline,
        "durable-only verdict must be Offline under tight thresholds at 10m future"
    );
    // A just-emitted timeline heartbeat (ts ≈ now) lifts the verdict to Active.
    let hb_ts = hb.ts;
    let just_after_hb = hb_ts + 500; // 0.5 s after the heartbeat
    assert_eq!(
        tight_cfg.liveness_combined(&bob_after_hb, Some(hb_ts), just_after_hb),
        Liveness::Active,
        "timeline heartbeat must lift combined verdict to Active (issue #250)"
    );
    // When the heartbeat itself is old enough, combined verdict follows it down.
    let long_after_hb = hb_ts + 10_000; // 10 s after the heartbeat (past 5 s offline threshold)
    assert_eq!(
        tight_cfg.liveness_combined(&bob_after_hb, Some(hb_ts), long_after_hb),
        Liveness::Offline,
        "stale timeline heartbeat must not prevent Offline verdict"
    );

    // ---- Criterion: the `--json` agent output shape is stable. ----
    // Check both the legacy `AgentState` shape (used by integration helpers)
    // and the new `AgentListing` envelope shape (used by `agent list/show --json`).
    assert_stable_agent_json(&bob_after_hb, &bob_signing.key_id());
    assert_stable_agent_json(alice_seen_by_bob, &alice_signing.key_id());
    assert_stable_agent_listing_json(&bob_after_hb, Liveness::Active, &bob_signing.key_id());
    assert_stable_agent_listing_json(alice_seen_by_bob, Liveness::Active, &alice_signing.key_id());
}

/// Device verification e2e coverage (issue #240).
///
/// Proves that [`mx_agent_daemon::sender_verified`] returns something other
/// than `Some(true)` for an unverified peer, and `Some(true)` after
/// [`mx_agent_daemon::manual_verify`], against the daemon's real Matrix SDK
/// crypto store and a live homeserver. Combined with the
/// `enforce_verified_device` unit tests in `exec.rs`, this pins the
/// `require_verified_device` exec gate end-to-end:
///
/// - the SDK correctly tracks peer device verification status in the local
///   crypto store, and
/// - [`mx_agent_daemon::list_devices`] reflects the updated status immediately
///   after a successful manual verify.
///
/// Uses an encrypted room so device keys are automatically exchanged during
/// the sync loop's Megolm key negotiation, ensuring peer devices are visible
/// in Alice's local crypto store before `sender_verified` is called.
///
/// Run via `scripts/matrix_integration_test.sh` alongside the rest of the
/// Matrix integration suite.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_device_manual_verify_and_sender_verified() {
    let _serial = enter_single_threaded_section();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    // Fully isolated state: both sync token and crypto store go to a unique
    // throwaway dir (same pattern as live_matrix_backed_remote_exec_*).
    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");

    // Both sync loops must run so device keys are uploaded and shared.
    let running = Arc::new(AtomicBool::new(true));
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };
    // Bob's sync loop drives Megolm key sharing with Alice's device.
    let bob_sync = {
        let bob = bob.clone();
        tokio::spawn(async move {
            let _ = bob.sync(SyncSettings::default()).await;
        })
    };

    // An encrypted room ensures the SDK exchanges device keys between users,
    // populating Alice's local crypto store with Bob's device information.
    let room = create_encrypted_room(&bob, "mx-agent device verify e2e").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins encrypted room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    let bob_id = bob.user_id().expect("bob user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;

    // Wait for Alice's crypto store to see Bob's devices. In a shared encrypted
    // room the SDK tracks peer device lists automatically during sync.
    let bob_id_str = bob_id.as_str();
    let bob_devices = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match mx_agent_daemon::list_devices(&alice, bob_id_str).await {
                Ok(devs) if !devs.is_empty() => return devs,
                _ => {}
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("alice should see bob's devices after device-key exchange in encrypted room");

    // Before manual verification: all of Bob's devices should be unverified.
    assert!(
        bob_devices.iter().all(|d| !d.verified),
        "bob's devices must start unverified; got {bob_devices:?}"
    );

    // `sender_verified` must return None or Some(false) before any verification.
    // Either value causes `enforce_verified_device` to reject the exec when
    // `require_verified_device = true` is set in policy.
    let pre_verified = mx_agent_daemon::sender_verified(&alice, bob_id_str).await;
    assert!(
        pre_verified != Some(true),
        "`sender_verified` must return None or Some(false) before `manual_verify`; \
         got {pre_verified:?}"
    );

    // Verify all of Bob's known devices in a retry loop. The background sync
    // loop continuously downloads device keys (the homeserver accumulates one
    // device per `login_password` call across prior tests in the same CI run),
    // so new devices may appear between `list_devices` and `sender_verified`.
    // Looping until `sender_verified` returns `Some(true)` is the only race-
    // free approach: each pass re-queries the full current set and re-verifies
    // any new arrivals before checking the combined verdict.
    //
    // No fingerprint check in tests — fingerprint matching is covered by the
    // `normalize_fingerprint` unit tests in `verification.rs`.
    let bob_device = bob_devices.first().expect("bob has at least one device");
    let post_verified = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let current = mx_agent_daemon::list_devices(&alice, bob_id_str)
                .await
                .unwrap_or_default();
            for device in &current {
                let _ = mx_agent_daemon::manual_verify(&alice, bob_id_str, &device.device_id, None)
                    .await;
            }
            if mx_agent_daemon::sender_verified(&alice, bob_id_str).await == Some(true) {
                return Some(true);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or(None);
    assert_eq!(
        post_verified,
        Some(true),
        "`sender_verified` must return `Some(true)` after `manual_verify`; \
         got {post_verified:?}"
    );

    // `list_devices` must reflect the new verified status immediately.
    let after_devices = mx_agent_daemon::list_devices(&alice, bob_id_str)
        .await
        .expect("list devices after verify");
    assert!(
        after_devices
            .iter()
            .find(|d| d.device_id == bob_device.device_id)
            .is_some_and(|d| d.verified),
        "device must be marked verified in list after manual_verify; got {after_devices:?}"
    );

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    bob_sync.abort();
    std::env::remove_var(ENV_DATA_DIR);
}

/// Server-side key backup / recovery e2e coverage (issue #240).
///
/// Provisions SSSS + server-side key backup via `enable_recovery` against a
/// live homeserver and asserts `recovery_status` reports `"enabled"` with an
/// active backup. Also checks the recovery key is redacted in `Debug` output
/// (exercising the [`crate::session::Secret`] wrapper on the IPC surface).
///
/// The full "restore across daemon restart" scenario — re-provision onto a fresh
/// device with an empty crypto store, then call `recover` with the one-time key
/// to regain decryptability of previously-encrypted history — is now covered live
/// by [`live_key_backup_restore_across_reprovision`] (issue #260; it resolves the
/// two blockers noted here by doing a second `login_password` for device B and
/// reading the key via `Secret::expose`). The enable + status path tested here
/// proves the provisioning path works end-to-end with a real homeserver; the
/// `recover` round-trip is also covered by unit tests in `verification.rs`.
///
/// Run via `scripts/matrix_integration_test.sh` alongside the rest of the
/// Matrix integration suite.
///
/// ## Isolation: this test needs a pristine cross-signing identity
///
/// Unlike the other live tests, this one calls `bootstrap_cross_signing` and
/// asserts the device ends up holding the **private** master key. That only
/// happens when the account has *no* cross-signing identity on the server yet:
/// `bootstrap_cross_signing_if_needed` correctly **no-ops** when the server
/// already advertises one (the documented re-provision path is then `recover`
/// with the backup key, not a re-bootstrap). Because a Matrix account keeps its
/// cross-signing identity server-side, reusing the shared `MX_AGENT_TEST_USER`
/// makes this test pass on a pristine homeserver but fail on every subsequent
/// run. It therefore logs in as a **dedicated, freshly-registered user**
/// (`MX_AGENT_TEST_RECOVERY_USER`, provisioned per run by the harness) so each
/// run starts from a clean cross-signing state. Do not collapse this back onto
/// the shared user — that reintroduces the cross-run flake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_recovery_enable_and_status() {
    let _serial = enter_single_threaded_section();
    // Enable logging so CI captures daemon decisions on failure (--nocapture).
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    // Prefer the per-run recovery user (pristine cross-signing state); fall back
    // to the shared user so a direct `cargo test` invocation still runs (it is
    // only hermetic against a freshly-reset homeserver — see the doc comment).
    let alice_user = std::env::var("MX_AGENT_TEST_RECOVERY_USER")
        .unwrap_or_else(|_| required_env("MX_AGENT_TEST_USER"));
    let alice_pass = std::env::var("MX_AGENT_TEST_RECOVERY_PASSWORD")
        .unwrap_or_else(|_| required_env("MX_AGENT_TEST_PASSWORD"));

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");

    // Drive the sync loop so device keys are uploaded to the homeserver before
    // enabling SSSS — key backup requires a live E2EE session on the server.
    let running = Arc::new(AtomicBool::new(true));
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };

    // Wait for at least one successful sync: device keys must be on the server.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            {
                let h = health.lock().unwrap();
                if h.state == SyncState::Healthy && h.total_syncs > 0 {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("sync loop must reach Healthy before enabling recovery");

    // Bootstrap cross-signing before SSSS; idempotent if already set up.
    let cs_status = mx_agent_daemon::bootstrap_cross_signing(&alice)
        .await
        .expect("cross-signing bootstrap should succeed before enabling recovery");
    // All three cross-signing keys must be present after a successful bootstrap.
    assert!(
        cs_status.has_master,
        "bootstrap_cross_signing must provision a master key; status: {cs_status:?}"
    );
    assert!(
        cs_status.complete,
        "cross-signing identity must be complete after bootstrap; status: {cs_status:?}"
    );
    // `cross_signing_status` must report the same state on a second call.
    let cs_status2 = mx_agent_daemon::cross_signing_status(&alice).await;
    assert!(
        cs_status2.has_master,
        "cross_signing_status must see the master key after bootstrap; got {cs_status2:?}"
    );
    assert_eq!(
        cs_status2.complete, cs_status.complete,
        "cross_signing_status must be consistent with bootstrap result; \
         bootstrap: {cs_status:?}, status: {cs_status2:?}"
    );

    // Provision SSSS + server-side key backup.
    let result = mx_agent_daemon::enable_recovery(&alice)
        .await
        .expect("enable_recovery should succeed against a live homeserver");

    // Status must report enabled with an active key backup.
    assert_eq!(
        result.status.state, "enabled",
        "recovery state after enable must be 'enabled'; got {:?}",
        result.status
    );
    assert!(
        result.status.backup_enabled,
        "key backup must be enabled after enable_recovery; got {:?}",
        result.status
    );

    // The recovery key must be redacted in Debug (Secret wrapper): only
    // `***redacted***` should appear, not the actual key material.
    let key_debug = format!("{:?}", result.recovery_key);
    assert!(
        key_debug.contains("***redacted***"),
        "recovery key must be redacted in Debug output; got: {key_debug}"
    );

    // `recovery_status` returns the same state without re-enabling.
    let status2 = mx_agent_daemon::recovery_status(&alice).await;
    assert_eq!(
        status2.state, "enabled",
        "recovery_status must still report 'enabled'; got {status2:?}"
    );
    assert!(
        status2.backup_enabled,
        "key backup must remain enabled on a repeated status check; got {status2:?}"
    );

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
}

/// `require_verified_device` exec gate end-to-end coverage (issue #240).
///
/// Proves the full verified-device happy path and unverified-device rejection
/// path through the live Matrix exec pipeline:
///
/// 1. **Unverified-device rejection**: Alice's daemon runs with policy
///    `require_verified_device = true` for Bob. Bob sends a signed exec request.
///    Alice's `handle_live_exec_request` calls `sender_verified` (Bob's device is
///    not yet verified) and rejects the request with `"unverified_device"`.
///
/// 2. **Verified-device happy path**: Alice manually verifies Bob's device via
///    `manual_verify`. The same exec request from Bob is now accepted and runs to
///    completion.
///
/// Combined with the `enforce_verified_device` unit tests in `exec.rs` and
/// `live_device_manual_verify_and_sender_verified`, this closes the e2e gap for
/// issue #240 §5 (verified-device happy path; unverified-device handling).
///
/// Run via `scripts/matrix_integration_test.sh` alongside the rest of the Matrix
/// integration suite.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_require_verified_device_gate() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester_agent = bob.user_id().expect("bob user id").to_string();
    let bob_id = bob.user_id().expect("bob user id").to_owned();

    // An encrypted room ensures device keys are exchanged between Alice and Bob:
    // without E2EE, Alice's crypto store never learns Bob's device, and
    // `sender_verified` returns `None` (indeterminate) rather than `Some(false)`.
    // Both `None` and `Some(false)` trigger rejection when `require_verified_device`
    // is set, so the test is valid either way, but the encrypted room makes the
    // verified phase more realistic.
    let room = create_encrypted_room(&bob, "mx-agent require-verified-device e2e").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins encrypted room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;

    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester_agent.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 2,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 2,
        },
    )
    .await
    .expect("register target agent");

    // Trust Bob's signing key; policy has `require_verified_device = true` so
    // Alice's daemon will reject exec requests from an unverified Matrix device
    // even when the signing key and policy otherwise permit the command.
    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
require_verified_device = true
"#,
            room = room_id.as_str(),
            agent = requester_agent,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    let subscribers = ExecSubscriberRegistry::new();
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &alice,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };
    let bob_sync_paths = paths_in(data_dir.join("bob-sync"));
    bob_sync_paths.ensure_data_dir().expect("bob sync dir");
    let bob_sync = {
        let bob = bob.clone();
        let paths = bob_sync_paths.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &bob,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };

    save_session(&paths, &bob_session).expect("save requester session");

    // ---- Phase 1: exec from an unverified device must be rejected ----
    //
    // Bob's device is not (yet) verified in Alice's crypto store. Alice's
    // `handle_live_exec_request` calls `sender_verified` (which returns either
    // `None` or `Some(false)`) and then `enforce_verified_device` rejects with
    // `ExecRejection::UnverifiedDevice`, surfaced as reason `"unverified_device"`.
    let rejected = start_exec_matrix(
        &ExecStartParams {
            room: Some(room_id.to_string()),
            agent: Some(TARGET_AGENT.to_string()),
            command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
            cwd: Some(cwd.clone()),
            stdin: None,
            stream: true,
            pty: false,
            task: None,
            strict_stream: false,
            env: Default::default(),
            timeout_ms: None,
            invocation_id: None,
        },
        &subscribers,
    )
    .await;
    match &rejected.outcome {
        ExecOutcome::Error { message, .. } => {
            assert!(
                message.contains("unverified_device"),
                "exec from unverified device must be rejected with 'unverified_device' reason; \
                 got: {message:?}"
            );
        }
        other => panic!("expected exec rejection for unverified device; got {other:?}"),
    }

    // ---- Phase 2: manually verify Bob's device on Alice's client ----
    //
    // Verify all of Bob's known devices in a retry loop (same race-free approach
    // as `live_device_manual_verify_and_sender_verified`): the background sync
    // loop may download additional devices between passes (the homeserver
    // accumulates one device per `login_password` call across prior tests), so
    // each pass re-queries and re-verifies the full current set before checking
    // the combined `sender_verified` verdict. The loop also handles the case
    // where no devices are visible yet (it waits until device key exchange
    // completes in the encrypted room).
    let bob_id_str = bob_id.as_str();
    let verified = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let current = mx_agent_daemon::list_devices(&alice, bob_id_str)
                .await
                .unwrap_or_default();
            for device in &current {
                let _ = mx_agent_daemon::manual_verify(&alice, bob_id_str, &device.device_id, None)
                    .await;
            }
            if mx_agent_daemon::sender_verified(&alice, bob_id_str).await == Some(true) {
                return Some(true);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or(None);
    assert_eq!(
        verified,
        Some(true),
        "`sender_verified` must return `Some(true)` after manual_verify; got {verified:?}"
    );

    // ---- Phase 3: exec from the now-verified device must succeed ----
    //
    // Alice's `handle_live_exec_request` calls `sender_verified` again; this time
    // it returns `Some(true)` because Bob's device was manually verified above.
    // `enforce_verified_device` passes, the exec runs, and the outcome is `Ok`.
    let accepted = start_exec_matrix(
        &ExecStartParams {
            room: Some(room_id.to_string()),
            agent: Some(TARGET_AGENT.to_string()),
            command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
            cwd: Some(cwd.clone()),
            stdin: None,
            stream: true,
            pty: false,
            task: None,
            strict_stream: false,
            env: Default::default(),
            timeout_ms: None,
            invocation_id: None,
        },
        &subscribers,
    )
    .await;
    match &accepted.outcome {
        ExecOutcome::Ok { frames } => {
            assert!(
                matches!(frames.last(), Some(ExecFrame::Finished(f)) if f.exit_code == Some(0)),
                "exec from verified device must succeed with exit 0; frames: {frames:?}"
            );
        }
        other => panic!("expected exec to succeed after device verification; got {other:?}"),
    }

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    bob_sync
        .await
        .expect("bob sync joins")
        .expect("bob sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");
}

/// Workspace rooms are created without E2EE — regression guard for #270 / #249.
///
/// Pins the security invariant that [`create_workspace`] does NOT enable
/// room-level encryption. Remote `exec`/`call`/`share` events sent into
/// workspace rooms are therefore **cleartext timeline events** readable by
/// the homeserver operator in this alpha. The documentation in
/// `docs/cli-reference.md` (corrected by #270) correctly reflects this:
/// operations are Ed25519-**signed** for authenticity but NOT
/// end-to-end encrypted.
///
/// This test guards against a silent regression: if `create_workspace` were
/// ever to accidentally enable `m.room.encryption`, the over-claim in the
/// docs would become factually true and the doc-lint guard in
/// `scripts/check-doc-claims.sh` would become incorrect in the opposite
/// direction. Both would need updating if workspace E2EE actually lands
/// (issue #249).
///
/// Two scenarios:
/// 1. **Both private and public workspaces report `encrypted = false`** via the
///    [`WorkspaceInfo`] summary, which reads `room.encryption_state()`.
/// 2. **An observer (Bob) can read an exec-typed event as cleartext** from the
///    public workspace: the event has no `encryption_info()` wrapper, which
///    is what `m.room.encrypted` events would carry.
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn workspace_room_is_created_without_encryption() {
    let _serial = enter_single_threaded_section();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login should succeed");
    let alice = restore_client(&alice_session)
        .await
        .expect("alice session restore should succeed");
    // Bob is the homeserver-operator stand-in: he must be able to read Alice's
    // workspace events as plaintext without any decryption step.
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login should succeed");
    let bob = restore_client(&bob_session)
        .await
        .expect("bob session restore should succeed");

    // ── Criterion 1: private workspace room must NOT be E2EE encrypted ────────
    let private_ws = create_workspace(
        &alice,
        &CreateWorkspaceOptions {
            name: Some("it-privacy-private".to_string()),
            topic: None,
            alias: None,
            visibility: WorkspaceVisibility::Private,
            e2ee: false,
        },
    )
    .await
    .expect("create private workspace");

    assert!(
        !private_ws.encrypted,
        "private workspace must NOT have E2EE enabled (exec/call traffic is signed \
         but cleartext in this alpha — see #249 / #270)"
    );

    // ── Criterion 1 (cont.): public workspace room must NOT be E2EE encrypted ─
    let public_ws = create_workspace(
        &alice,
        &CreateWorkspaceOptions {
            name: Some("it-privacy-public".to_string()),
            topic: None,
            alias: None,
            visibility: WorkspaceVisibility::Public,
            e2ee: false,
        },
    )
    .await
    .expect("create public workspace");

    assert!(
        !public_ws.encrypted,
        "public workspace must NOT have E2EE enabled (exec/call traffic is signed \
         but cleartext in this alpha — see #249 / #270)"
    );

    // ── Criterion 2: an observer reads an exec event as cleartext ─────────────
    //
    // Alice sends a synthetic `com.mxagent.exec.request.v1` marker into the
    // public workspace room (the exact event type the remote exec path uses).
    // Bob joins and fetches the event; it must carry no `encryption_info()` —
    // a homeserver operator can read the full payload.
    let pub_room_id: OwnedRoomId = public_ws.room_id.parse().expect("valid room id");
    let alice_room = alice
        .get_room(&pub_room_id)
        .expect("alice should own the public workspace room");

    let event_id = alice_room
        .send_raw(
            timeline::EXEC_REQUEST,
            json!({ "_test": "cleartext-marker-270" }),
        )
        .await
        .expect("send marker event")
        .response
        .event_id;

    bob.join_room_by_id(&pub_room_id)
        .await
        .expect("bob joins public workspace room");
    let bob_room = bob
        .get_room(&pub_room_id)
        .expect("bob sees the public workspace room");

    let observed = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(ev) = bob_room.event(&event_id, None).await {
                return ev;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("bob should fetch the timeline event within 30 s");

    assert!(
        observed.encryption_info().is_none(),
        "exec request sent to a workspace room must be a cleartext timeline event \
         with no encryption wrapper — the homeserver operator can read it (#270)"
    );

    std::env::remove_var(ENV_DATA_DIR);
}

/// Workspace creation with E2EE enabled — contract test for issue #249.
///
/// Proves three properties of the encrypted-on-create workspace path end-to-end
/// against a real homeserver:
///
/// 1. **Immediate result.** [`create_workspace`] with `e2ee: true` returns a
///    [`WorkspaceInfo`] with `encrypted: true`, even before the client has synced
///    the room's `m.room.encryption` state event. The
///    [`WorkspaceInfo::from_room_with_e2ee`] helper ORs the *requested* flag with
///    the live store state so the returned info never under-reports.
///
/// 2. **Live room state.** After the daemon's sync loop processes the room's
///    `initial_state`, `room.encryption_state().is_encrypted()` reports `true`,
///    proving the `m.room.encryption` event was actually sent in `initial_state`
///    and not just OR-d into the return value.
///
/// 3. **Privileged event decrypt-and-route.** A signed `com.mxagent.exec.request.v1`
///    event sent into the encrypted-on-create workspace by the requester (Bob)
///    decrypts correctly at the daemon (Alice) and passes the real
///    [`authorize_exec_request`] pipeline, proving that encryption-on-create
///    composes with the existing fail-safe receive path (issue #61,
///    `daemon_e2ee_privileged_event_coverage`).
///
/// **Security note:** this test does NOT weaken the authorization model. Room
/// encryption is a transport/confidentiality property only; all signed-request,
/// trust-store, and policy checks remain in place unchanged. Encrypting the room
/// changes only what the homeserver operator can read — not who may cause
/// execution (architecture §1.2).
///
/// The "default create is unencrypted" counterpart is covered by
/// [`workspace_room_is_created_without_encryption`].
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn workspace_create_with_e2ee_enables_encryption_and_routes_privileged_events() {
    let _serial = enter_single_threaded_section();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    // Isolate this test's persisted state without touching the process-global
    // data-dir env var (same pattern as daemon_e2ee_privileged_event_coverage).
    let paths = paths_in(throwaway_data_dir());
    paths.ensure_data_dir().expect("create data dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };

    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login should succeed");
    let alice = restore_client(&alice_session)
        .await
        .expect("alice session restore should succeed");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login should succeed");
    let bob = restore_client(&bob_session)
        .await
        .expect("bob session restore should succeed");

    // Drive the daemon's real /sync loop: it uploads device/one-time keys and
    // decrypts incoming encrypted events.
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(
                &alice,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
            )
            .await
        })
    };
    // The requester also needs a live sync so its crypto state (device keys,
    // to-device key sharing) is established before it sends encrypted events.
    let bob_sync = {
        let bob = bob.clone();
        tokio::spawn(async move {
            let _ = bob.sync(SyncSettings::default()).await;
        })
    };

    // The requester's signing identity and a trust store that accepts it.
    let signing = load_or_create_signing_key(&paths).expect("requester signing key");
    let key_id = signing.key_id();
    let verifying = signing.verifying_key();
    let mut trust = TrustStore::default();
    trust.approve(REQUESTER_AGENT, &key_id, None, None, None);

    let alice_id = alice.user_id().expect("alice has a user id").to_owned();

    // ── Criterion 1: create_workspace with e2ee: true returns encrypted: true ──
    //
    // Use a public workspace so Bob (the requester) can join without an invite.
    // WorkspaceInfo::from_room_with_e2ee ORs the requested flag with the live
    // room state, ensuring the returned info is always correct even if the local
    // store hasn't processed the initial_state encryption event yet.
    let ws_info = create_workspace(
        &alice,
        &CreateWorkspaceOptions {
            name: Some("it-e2ee-workspace".to_string()),
            topic: None,
            alias: None,
            visibility: WorkspaceVisibility::Public,
            e2ee: true,
        },
    )
    .await
    .expect("create encrypted workspace should succeed");

    assert!(
        ws_info.encrypted,
        "create_workspace with e2ee: true must return WorkspaceInfo.encrypted == true \
         (issue #249); got: {ws_info:?}"
    );
    let ws_room_id: OwnedRoomId = ws_info.room_id.parse().expect("valid workspace room id");

    // ── Criterion 2: after sync the live room reports is_encrypted() == true ───
    //
    // The m.room.encryption initial_state event must be reflected in the client's
    // local store after the sync loop processes it. Poll with a bounded deadline
    // instead of a fixed sleep to avoid flakes.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(room) = alice.get_room(&ws_room_id) {
                if room.encryption_state().is_encrypted() {
                    return;
                }
            }
            let _ = alice.sync_once(SyncSettings::default()).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect(
        "workspace room created with e2ee: true must report is_encrypted() == true after sync \
         (issue #249); the m.room.encryption event was not reflected in room state",
    );

    // ── Criterion 3: privileged event in encrypted-on-create room decrypts ─────
    //
    // Bob joins the workspace and sends a signed exec request as an encrypted
    // Matrix event. Alice's daemon decrypts it over /sync and the real
    // authorization pipeline admits it — proving encryption-on-create composes
    // with the existing fail-safe receive path.
    let alice_room = alice
        .get_room(&ws_room_id)
        .expect("alice owns the workspace room");

    bob.join_room_by_id(&ws_room_id)
        .await
        .expect("bob joins the encrypted workspace");

    // Wait until Alice is visible to Bob as a joined member so the megolm room
    // key is shared with Alice's device before Bob sends.
    let bob_room = bob
        .get_room(&ws_room_id)
        .expect("bob sees the workspace room");
    wait_for_joined_member(&bob_room, &alice_id).await;

    let policy = permissive_policy(ws_room_id.as_str(), REQUESTER_AGENT);

    // Build and send an encrypted, signed exec request from Bob's perspective.
    let exec_content = build_signed_exec_request(
        signing.signing_key(),
        &key_id,
        "inv_e2ee_wscreate",
        "req_e2ee_wscreate",
        "e2ee-wscreate-nonce",
        "2026-06-04T12:00:00Z",
        "2099-01-01T00:00:00Z",
        &exec_options(),
    )
    .expect("sign exec request for encrypted workspace");

    let exec_event_id = bob_room
        .send_raw(timeline::EXEC_REQUEST, exec_content)
        .await
        .expect("send encrypted exec request into workspace room")
        .response
        .event_id;

    // Alice's client must decrypt the event. decrypted_content panics on
    // timeout — an undecryptable privileged event is a regression in the path.
    let exec_decrypted = decrypted_content(&alice_room, &exec_event_id).await;

    // The decrypted content must authorize through the real pipeline.
    let authorized = authorize_exec_request(
        &exec_decrypted,
        &verifying,
        &trust,
        &policy,
        ws_room_id.as_str(),
        REQUESTER_AGENT,
        TARGET_AGENT,
    )
    .expect(
        "decrypted exec metadata in an encrypted-on-create workspace room must authorize \
         (issue #249)",
    );
    assert_eq!(
        authorized.invocation_id, "inv_e2ee_wscreate",
        "authorized exec must carry the expected invocation id"
    );
    assert_eq!(
        authorized.command,
        vec!["cargo", "test"],
        "authorized exec must carry the expected command"
    );

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync task should join")
        .expect("alice sync loop should exit cleanly");
    bob_sync.abort();
}

/// Live scheduler rejects forged approval decisions from non-daemon room members
/// (issue #264: approval-decision sender verification end-to-end).
///
/// Security invariant under test: `read_verified_approval_decisions` admits only
/// decisions whose Matrix `sender` equals the host daemon's own user id (`local_user`).
/// Room membership alone never satisfies the approval gate.
///
/// Scenario:
/// 1. A task with `requires_approval` is published — the scheduler holds it
///    (fail-closed) and enqueues a [`PendingApproval`] entry.
/// 2. Bob (a room member who is NOT the daemon) publishes a raw
///    `com.mxagent.approval.decision.v1` event with `decision: "approved"` for
///    the held task. The scheduler scans the timeline, rejects Bob's event
///    (sender ≠ daemon user), and the task stays `pending`. The sentinel
///    command is never spawned.
/// 3. Alice's daemon issues a legitimately signed decision via
///    [`decide_approval_for_session`]. The scheduler verifies sender + signature
///    + nonce, releases the task, and the task runs to `succeeded`. The
///    sentinel is now created.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_scheduler_rejects_forged_approval_decisions() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");
    // The sentinel file is written by the task's command. It must NOT exist
    // while the task is held (forged decision) and MUST exist after approval.
    let sentinel = cwd.join("forged-approval-ran");
    // Creator identity whose policy marks exec requests `requires_approval`.
    let approver = "@approver:mx-agent.test";

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester = bob.user_id().expect("bob user id").to_string();

    let room = create_public_room(&bob, "mx-agent forged-approval security test").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 2,
        },
    )
    .await
    .expect("register target agent");

    // Trust the daemon signing key and configure policy: the approver's exec
    // actions are allowed but require a human decision before they run.
    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{approver}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
requires_approval = true
"#,
            room = room_id.as_str(),
            approver = approver,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    // Publish the approval-required task. Its command writes the sentinel;
    // it must NOT run until a legitimate signed decision is issued.
    create_task(
        &bob,
        &signed_exec_task(
            room_id.as_str(),
            "task-forged",
            &["sh", "-c", &format!("touch {}", sentinel.to_string_lossy())],
            &cwd,
            Vec::new(),
            &signing,
            approver,
        ),
    )
    .await
    .expect("create approval-required task");

    // Start Alice's /sync loop and the scheduler loop.
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };
    let scheduler = {
        let alice = alice.clone();
        let running = running.clone();
        std::thread::spawn(move || {
            run_scheduler_loop(
                alice,
                ExecSubscriberRegistry::new(),
                TaskDispatchMode::Local,
                running,
                Duration::from_secs(1),
            );
        })
    };

    let list_opts = ListTasksOptions {
        room: room_id.to_string(),
        state: None,
        assigned_to: None,
    };
    let approval_id = "approval:task-forged";

    // Wait for the scheduler to hold the task (approval entry appears in the
    // local queue). This confirms the task has been seen and is being held
    // fail-closed before any decision.
    let queue_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let pending = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
        if pending.iter().any(|p| p.request_id() == approval_id) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < queue_deadline,
            "scheduler should enqueue the pending approval within 60 s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ── Security negative test: Bob (non-daemon user) publishes a forged
    //    `approved` decision for the held task (issue #264 attack vector). ──
    //
    // Bob's Matrix user id is NOT the daemon's `local_user` (Alice's user id).
    // `read_verified_approval_decisions` rejects this event at the sender check
    // and never maps it into the decisions HashMap the gate consults. The task
    // must stay `pending`; the sentinel command must never spawn.
    room.send_raw(
        timeline::APPROVAL_DECISION,
        json!({
            "request_id": approval_id,
            "decision": "approved",
            "approved_by": bob.user_id().expect("bob user id").as_str(),
            "created_at": "2026-06-10T12:00:00Z",
            "nonce": format!("forged-nonce-{}", std::process::id()),
            "expires_at": "2099-01-01T00:00:00Z"
        }),
    )
    .await
    .expect("bob publishes forged approved decision");

    // Allow 10+ scheduler passes (1 s interval) for the forged event to be
    // incorrectly acted on if the fix were absent. Then assert the task has
    // not been released and the command has not run.
    tokio::time::sleep(Duration::from_secs(10)).await;

    assert!(
        !sentinel.exists(),
        "forged approval decision from a room member must not spawn the command (issue #264)"
    );
    let held_state = list_tasks(&bob, &list_opts)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|t| t.task_id == "task-forged")
        .map(|t| t.state);
    assert_ne!(
        held_state.as_deref(),
        Some("succeeded"),
        "forged decision must not release the held task; state: {held_state:?}"
    );

    // ── Positive path: daemon issues a legitimately signed decision. ──
    //
    // `decide_approval_for_session` publishes a decision from Alice's Matrix
    // user (the daemon's own `local_user`), signed with the daemon's key and
    // carrying a single-use nonce. The scheduler verifies sender + signature +
    // replay material and releases the task; it runs to `succeeded`.
    decide_approval_for_session(
        &alice_session,
        &paths,
        approval_id,
        DECISION_APPROVED,
        alice_id.as_str(),
    )
    .await
    .expect("daemon approves the task over IPC");

    let approved_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut final_state = None;
    loop {
        if let Ok(tasks) = list_tasks(&bob, &list_opts).await {
            if let Some(t) = tasks.iter().find(|t| t.task_id == "task-forged") {
                final_state = Some(t.state.clone());
                if t.state == "succeeded" {
                    break;
                }
            }
        }
        if tokio::time::Instant::now() >= approved_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Dump task state for CI diagnostics.
    if let Ok(tasks) = list_tasks(&bob, &list_opts).await {
        for t in &tasks {
            eprintln!(
                "DIAG task={} state={} result={}",
                t.task_id,
                t.state,
                t.result
                    .as_ref()
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "null".to_string())
            );
        }
    }

    running.store(false, Ordering::SeqCst);
    scheduler.join().expect("scheduler thread joins");
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");

    assert_eq!(
        final_state.as_deref(),
        Some("succeeded"),
        "task approved by the daemon must run to succeeded; state: {final_state:?}"
    );
    assert!(
        sentinel.exists(),
        "legitimately approved task must spawn its command"
    );
}

/// Live named-`call` approval hold (issue #263).
///
/// Drives a real daemon sync loop against the live homeserver: Bob sends a
/// signed `com.mxagent.call.request.v1` to Alice's daemon under a policy that
/// marks the requesting agent with `requires_approval = true`. Three acceptance
/// criteria are verified end-to-end against the real `handle_live_call_request`
/// path:
///
/// 1. **Fail-closed hold** — no `com.mxagent.call.response.v1` is emitted; the
///    handler returns before `execute_authorized_call` is reached.
/// 2. **Approval request emitted** — a `com.mxagent.approval.request.v1` event
///    carrying the call's `request_id` appears in the room.
/// 3. **Queue durability** — a [`PendingApproval`] is written to the on-disk
///    queue and survives a queue reload; the summary names only the tool and no
///    call args leak into the queued record.
///
/// The non-approval path (immediate execution) is already covered end-to-end by
/// [`live_matrix_backed_remote_call_round_trips`]; this test focuses on the new
/// security guarantee.
///
/// Run via: `scripts/matrix_integration_test.sh`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_named_call_requires_approval_holds_and_enqueues() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester_agent = bob.user_id().expect("bob user id").to_string();

    let room = create_public_room(&bob, "mx-agent call approval hold test").await;
    let room_id = room.room_id().to_owned();
    alice.join_room_by_id(&room_id).await.expect("alice joins");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester_agent.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["call".to_string()],
            tools: vec!["run_tests@1.0.0".to_string()],
            cwd: "/home/me/code/mx-agent".to_string(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["call".to_string()],
            tools: vec!["run_tests@1.0.0".to_string()],
            cwd: "/home/me/code/mx-agent".to_string(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register target agent");

    // Trust the daemon's signing key so the call's signature check passes.
    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");

    // Policy: the tool is allowed but an operator decision is required before the
    // call executes — this is the requires_approval gate under test (issue #263).
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_tools = ["run_tests"]
requires_approval = true
"#,
            room = room_id.as_str(),
            agent = requester_agent,
        ),
    )
    .expect("write approval-required policy");

    // Start Alice's daemon sync loop so handle_live_call_request fires on the
    // incoming call request.
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };

    // Build and send the signed call request directly — `start_call_matrix`
    // blocks waiting for a `call.response` that a held call never emits, so
    // we build the request ourselves and fire it into the room.
    let invocation_id = format!("inv_call_approv_{}", std::process::id());
    let request_id = format!("req_call_approv_{}", std::process::id());
    save_session(&paths, &bob_session).expect("save requester session");
    let content = build_signed_call_request_for_target(
        signing.signing_key(),
        signing.key_id(),
        &invocation_id,
        &request_id,
        format!("nonce-approv-{}", std::process::id()),
        "2026-06-10T12:00:00Z",
        "2099-01-01T00:00:00Z",
        "run_tests",
        // Secret-like arg value to assert it never leaks into the approval queue.
        json!({ "package": "should_not_appear_in_approval" }),
        CallTargeting {
            requesting_agent: Some(requester_agent.clone()),
            target_agent: Some(TARGET_AGENT.to_string()),
        },
    )
    .expect("sign call request");

    let bob_room = bob.get_room(&room_id).expect("bob sees room");
    bob_room
        .send_raw(timeline::CALL_REQUEST, content)
        .await
        .expect("send approval-required call request");

    // Criterion 3: poll the local approval queue until the PendingApproval for
    // this call appears (bounded 60 s). The daemon's sync handler enqueues it
    // atomically via hold_call_for_approval before returning fail-closed.
    let queue_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let pending = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
        if pending.iter().any(|p| p.request_id() == request_id) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < queue_deadline,
            "daemon should enqueue a PendingApproval for the approval-required call within 60 s"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Validate queue entry: correct room, summary, invocation id, and no arg leak.
    let pending = list_pending_approvals(&paths, Some(room_id.as_str())).expect("list pending");
    let queued = pending
        .iter()
        .find(|p| p.request_id() == request_id)
        .expect("PendingApproval must be in queue for approval-required call");
    assert_eq!(queued.room_id, room_id.to_string());
    assert_eq!(queued.request.summary, "Call tool run_tests");
    assert_eq!(queued.request.invocation_id, invocation_id);
    let queue_json = serde_json::to_string(&queued).expect("serialize queued approval");
    assert!(
        !queue_json.contains("should_not_appear_in_approval"),
        "call args must not leak into the queued PendingApproval: {queue_json}"
    );

    // Queue reload: the entry must survive a fresh load (0600 persisted file).
    let reloaded = mx_agent_daemon::ApprovalQueue::load(&paths).expect("reload approval queue");
    assert!(
        reloaded.get(&request_id).is_some(),
        "PendingApproval must survive an approval queue reload"
    );

    // Criterion 2: a `com.mxagent.approval.request.v1` was emitted into the room
    // by the daemon's hold path. Paginate backward through the room timeline
    // (via Bob's client) and find the event with our request_id.
    let mut msg_request = MessagesOptions::backward();
    msg_request.limit = matrix_sdk::ruma::UInt::from(50_u32);
    let messages = bob_room
        .messages(msg_request)
        .await
        .expect("paginate room timeline");
    let approval_request_found = messages.chunk.iter().any(|event| {
        let raw = event.raw();
        let is_type = raw.get_field::<String>("type").ok().flatten().as_deref()
            == Some(timeline::APPROVAL_REQUEST);
        if !is_type {
            return false;
        }
        raw.get_field::<ApprovalRequest>("content")
            .ok()
            .flatten()
            .map(|r| r.request_id == request_id)
            .unwrap_or(false)
    });
    assert!(
        approval_request_found,
        "daemon must emit a com.mxagent.approval.request.v1 into the room when holding a call \
         (issue #263): no approval.request.v1 with request_id={request_id} found in timeline"
    );

    // Criterion 1: no `com.mxagent.call.response.v1` with our request_id was
    // emitted — the daemon returned before execute_authorized_call was reached.
    // The same backward page is sufficient since no other sync activity generates
    // a response for this request_id.
    let call_response_found = messages.chunk.iter().any(|event| {
        let raw = event.raw();
        let is_type = raw.get_field::<String>("type").ok().flatten().as_deref()
            == Some(timeline::CALL_RESPONSE);
        if !is_type {
            return false;
        }
        raw.get_field::<Value>("content")
            .ok()
            .flatten()
            .and_then(|c| {
                c.get("request_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s == request_id)
            })
            .unwrap_or(false)
    });
    assert!(
        !call_response_found,
        "daemon must NOT emit a call.response for an approval-required call before a decision \
         (issue #263): call.response with request_id={request_id} found in timeline"
    );

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");
}

/// Issue #306: approve a held live `exec` → it executes exactly once.
///
/// The sync loop's `RoutedEvent::ApprovalDecision` handler
/// (`handle_live_approval_decision`) verifies the decision, removes the hold,
/// re-authorizes the original request through the full pipeline, and spawns
/// it via `spawn_authorized_live_exec`.
///
/// Verifies:
/// 1. Exec held fail-closed: sentinel not created, PendingApproval queued with
///    `held_request` set (so the release path can recover the original request).
/// 2. Approve via [`decide_approval_for_session`] → daemon processes the
///    decision event, re-authorizes, and spawns the command.
/// 3. Sentinel file created within 60 s of approval (exactly-once execution).
/// 4. Queue entry removed after the decision is consumed.
///
/// Run via: `scripts/matrix_integration_test.sh`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_exec_held_approval_approve_releases_and_runs() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");
    let sentinel = cwd.join("approved-exec-ran");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester_agent = bob.user_id().expect("bob user id").to_string();
    let alice_id = alice.user_id().expect("alice user id").to_owned();

    let room = create_public_room(&bob, "mx-agent exec hold+approve release test (306)").await;
    let room_id = room.room_id().to_owned();
    alice.join_room_by_id(&room_id).await.expect("alice joins");
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice sees power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester_agent.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register target agent");

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
requires_approval = true
"#,
            room = room_id.as_str(),
            agent = requester_agent,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    // Alice's sync loop holds the exec when received and releases it once the
    // approval decision arrives.
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };

    // Send the signed exec request directly — `start_exec_matrix` would block
    // waiting for `exec.accepted`, which is only emitted after approval.
    let invocation_id = format!("inv_306_approve_{}", std::process::id());
    let request_id = format!("req_306_approve_{}", std::process::id());
    save_session(&paths, &bob_session).expect("save requester session");
    let bob_room = bob.get_room(&room_id).expect("bob sees room");
    let content = build_signed_exec_request(
        signing.signing_key(),
        signing.key_id(),
        &invocation_id,
        &request_id,
        format!("nonce-306-approve-{}", std::process::id()),
        "2026-06-13T00:00:00Z",
        "2099-01-01T00:00:00Z",
        &ExecRequestOptions {
            target_agent: TARGET_AGENT.to_string(),
            requesting_agent: requester_agent.clone(),
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("touch {}", sentinel.to_string_lossy()),
            ],
            cwd: cwd.to_string_lossy().into_owned(),
            env: BTreeMap::new(),
            stdin: false,
            stream: false,
            pty: false,
            timeout_ms: 30_000,
            task_id: None,
        },
    )
    .expect("sign exec request");
    bob_room
        .send_raw(timeline::EXEC_REQUEST, content)
        .await
        .expect("send approval-required exec request");

    // Wait for the daemon to enqueue the hold.
    let hold_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let pending = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
        if pending.iter().any(|p| p.request_id() == request_id) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < hold_deadline,
            "daemon should hold the approval-required exec within 60 s (issue #306)"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        !sentinel.exists(),
        "exec must not spawn while held pending approval (issue #306)"
    );
    // `held_request` must carry the original exec so the release path can spawn it.
    let queued = list_pending_approvals(&paths, Some(room_id.as_str()))
        .expect("list pending approvals")
        .into_iter()
        .find(|p| p.request_id() == request_id)
        .expect("PendingApproval must be queued for held exec");
    assert!(
        queued.held_request.is_some(),
        "PendingApproval.held_request must be set so the live release path can spawn it (issue #306)"
    );

    // Approve via the same IPC path as `mx-agent approval approve`.
    decide_approval_for_session(
        &alice_session,
        &paths,
        &request_id,
        DECISION_APPROVED,
        alice_id.as_str(),
    )
    .await
    .expect("approve held exec");

    // The daemon processes the decision on its next sync, re-authorizes, and
    // spawns the command. Poll for the sentinel (up to 60 s).
    let release_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if sentinel.exists() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < release_deadline,
            "released exec must spawn and create the sentinel within 60 s (issue #306)"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        sentinel.exists(),
        "sentinel must exist after approved exec executes (issue #306)"
    );
    let remaining = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
    assert!(
        !remaining.iter().any(|p| p.request_id() == request_id),
        "PendingApproval must be removed from queue after an approved live decision (issue #306)"
    );

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");
}

/// Issue #306: deny a held live `exec` → it never executes and the hold is removed.
///
/// Exercises the `denied-while-held` branch of `handle_live_approval_decision`:
/// `deny_held_exec` emits an `exec.rejected` (`approval_denied`) event and the
/// sentinel command never spawns.
///
/// Verifies:
/// 1. Exec held fail-closed (sentinel not created, PendingApproval queued).
/// 2. Deny via [`decide_approval_for_session`] → `deny_held_exec` runs; command
///    never spawns; queue entry removed.
/// 3. Sentinel does NOT exist after the denial and a grace period.
///
/// Run via: `scripts/matrix_integration_test.sh`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_exec_held_approval_deny_never_runs() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");
    let sentinel = cwd.join("denied-exec-must-not-run");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester_agent = bob.user_id().expect("bob user id").to_string();
    let alice_id = alice.user_id().expect("alice user id").to_owned();

    let room = create_public_room(&bob, "mx-agent exec hold+deny test (306)").await;
    let room_id = room.room_id().to_owned();
    alice.join_room_by_id(&room_id).await.expect("alice joins");
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice sees power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester_agent.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register target agent");

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
requires_approval = true
"#,
            room = room_id.as_str(),
            agent = requester_agent,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };

    let invocation_id = format!("inv_306_deny_{}", std::process::id());
    let request_id = format!("req_306_deny_{}", std::process::id());
    save_session(&paths, &bob_session).expect("save requester session");
    let bob_room = bob.get_room(&room_id).expect("bob sees room");
    let content = build_signed_exec_request(
        signing.signing_key(),
        signing.key_id(),
        &invocation_id,
        &request_id,
        format!("nonce-306-deny-{}", std::process::id()),
        "2026-06-13T00:00:00Z",
        "2099-01-01T00:00:00Z",
        &ExecRequestOptions {
            target_agent: TARGET_AGENT.to_string(),
            requesting_agent: requester_agent.clone(),
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("touch {}", sentinel.to_string_lossy()),
            ],
            cwd: cwd.to_string_lossy().into_owned(),
            env: BTreeMap::new(),
            stdin: false,
            stream: false,
            pty: false,
            timeout_ms: 30_000,
            task_id: None,
        },
    )
    .expect("sign exec request");
    bob_room
        .send_raw(timeline::EXEC_REQUEST, content)
        .await
        .expect("send approval-required exec request");

    // Wait for the hold to be enqueued.
    let hold_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let pending = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
        if pending.iter().any(|p| p.request_id() == request_id) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < hold_deadline,
            "daemon should hold the approval-required exec within 60 s (issue #306)"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        !sentinel.exists(),
        "exec must not spawn while held pending approval (issue #306)"
    );

    // Deny the hold.
    decide_approval_for_session(
        &alice_session,
        &paths,
        &request_id,
        DECISION_DENIED,
        alice_id.as_str(),
    )
    .await
    .expect("deny held exec");

    // Wait for the deny to be processed (queue entry removed on the daemon side).
    let deny_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let remaining = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
        if !remaining.iter().any(|p| p.request_id() == request_id) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deny_deadline,
            "PendingApproval must be removed from queue after a denied decision (issue #306)"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // After denial the command must never have spawned. A 3 s grace period is
    // enough — a spawned `sh -c touch …` finishes in milliseconds.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !sentinel.exists(),
        "denied exec must never spawn its command (issue #306)"
    );

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");
}

/// Issue #306: approve a held live `call` → it executes and a `call.response`
/// appears in the room timeline.
///
/// Mirrors [`live_exec_held_approval_approve_releases_and_runs`] for the named-call
/// path: `release_held_call` re-authorizes via `authorize_live_call`, runs the
/// tool via `execute_and_respond_call`, and emits a `com.mxagent.call.response.v1`
/// regardless of the tool's exit code.
///
/// Verifies:
/// 1. Call held fail-closed (no `call.response`, PendingApproval queued with
///    `held_request` set).
/// 2. Approve via [`decide_approval_for_session`] → `release_held_call` runs the
///    tool and emits `call.response`.
/// 3. A `call.response.v1` for our `request_id` appears in the room within 90 s.
/// 4. Queue entry removed after the decision.
///
/// Run via: `scripts/matrix_integration_test.sh`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_call_held_approval_approve_releases_and_runs() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester_agent = bob.user_id().expect("bob user id").to_string();
    let alice_id = alice.user_id().expect("alice user id").to_owned();

    let room = create_public_room(&bob, "mx-agent call hold+approve release test (306)").await;
    let room_id = room.room_id().to_owned();
    alice.join_room_by_id(&room_id).await.expect("alice joins");
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice sees power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester_agent.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["call".to_string()],
            tools: vec!["run_tests@1.0.0".to_string()],
            cwd: "/tmp".to_string(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["call".to_string()],
            tools: vec!["run_tests@1.0.0".to_string()],
            cwd: "/tmp".to_string(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register target agent");

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_tools = ["run_tests"]
requires_approval = true
"#,
            room = room_id.as_str(),
            agent = requester_agent,
        ),
    )
    .expect("write policy");

    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };

    // Send a signed call request directly — `start_call_matrix` blocks waiting
    // for `call.response`, which only arrives after the hold is released.
    let invocation_id = format!("inv_306_call_approve_{}", std::process::id());
    let request_id = format!("req_306_call_approve_{}", std::process::id());
    save_session(&paths, &bob_session).expect("save requester session");
    let bob_room = bob.get_room(&room_id).expect("bob sees room");
    let content = build_signed_call_request_for_target(
        signing.signing_key(),
        signing.key_id(),
        &invocation_id,
        &request_id,
        format!("nonce-306-call-approve-{}", std::process::id()),
        "2026-06-13T00:00:00Z",
        "2099-01-01T00:00:00Z",
        "run_tests",
        // Arg value deliberately distinct to confirm it stays out of the approval queue.
        json!({ "package": "nonexistent-package-306" }),
        CallTargeting {
            requesting_agent: Some(requester_agent.clone()),
            target_agent: Some(TARGET_AGENT.to_string()),
        },
    )
    .expect("sign call request");
    bob_room
        .send_raw(timeline::CALL_REQUEST, content)
        .await
        .expect("send approval-required call request");

    // Wait for the hold to be enqueued.
    let hold_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let pending = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
        if pending.iter().any(|p| p.request_id() == request_id) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < hold_deadline,
            "daemon should hold the approval-required call within 60 s (issue #306)"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    // `held_request` must carry the original call so `release_held_call` can run it.
    let queued = list_pending_approvals(&paths, Some(room_id.as_str()))
        .expect("list pending")
        .into_iter()
        .find(|p| p.request_id() == request_id)
        .expect("PendingApproval must be queued for held call");
    assert!(
        queued.held_request.is_some(),
        "PendingApproval.held_request must be set for live call holds (issue #306)"
    );

    // No `call.response` must have been emitted while the call is held.
    let mut msg_opts = MessagesOptions::backward();
    msg_opts.limit = matrix_sdk::ruma::UInt::from(50_u32);
    let messages = bob_room
        .messages(msg_opts)
        .await
        .expect("paginate timeline");
    let pre_response = messages.chunk.iter().any(|event| {
        let raw = event.raw();
        raw.get_field::<String>("type").ok().flatten().as_deref() == Some(timeline::CALL_RESPONSE)
            && raw
                .get_field::<Value>("content")
                .ok()
                .flatten()
                .and_then(|c| {
                    c.get("request_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s == request_id)
                })
                .unwrap_or(false)
    });
    assert!(
        !pre_response,
        "daemon must NOT emit call.response before an approval decision (issue #306)"
    );

    // Approve.
    decide_approval_for_session(
        &alice_session,
        &paths,
        &request_id,
        DECISION_APPROVED,
        alice_id.as_str(),
    )
    .await
    .expect("approve held call");

    // Poll for the `call.response` to appear in the room timeline. The tool may
    // fail (cargo test on a nonexistent package) but a response is always emitted
    // — what matters is that it exists, proving the release happened.
    let release_deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let response_found = loop {
        let mut poll_opts = MessagesOptions::backward();
        poll_opts.limit = matrix_sdk::ruma::UInt::from(50_u32);
        if let Ok(messages) = bob_room.messages(poll_opts).await {
            let found = messages.chunk.iter().any(|event| {
                let raw = event.raw();
                raw.get_field::<String>("type").ok().flatten().as_deref()
                    == Some(timeline::CALL_RESPONSE)
                    && raw
                        .get_field::<Value>("content")
                        .ok()
                        .flatten()
                        .and_then(|c| {
                            c.get("request_id")
                                .and_then(|v| v.as_str())
                                .map(|s| s == request_id)
                        })
                        .unwrap_or(false)
            });
            if found {
                break true;
            }
        }
        if tokio::time::Instant::now() >= release_deadline {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert!(
        response_found,
        "a call.response.v1 must appear in the timeline after approving a held call (issue #306): \
         request_id={request_id}"
    );

    let remaining = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
    assert!(
        !remaining.iter().any(|p| p.request_id() == request_id),
        "PendingApproval must be removed from queue after an approved live call decision (issue #306)"
    );

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");
}

/// Issue #306: a forged unsigned approval decision from an untrusted sender is
/// ignored — the hold stays queued and the exec never runs.
///
/// Security invariant: `handle_live_approval_decision` checks the event's
/// **Matrix sender** against the daemon's local user and the room's approver
/// allowlist before verifying any signature. Bob (the requester) is neither, so
/// his decision event is dropped at the `untrusted_sender` check without touching
/// the hold.
///
/// Verifies:
/// 1. Exec held fail-closed (sentinel not created, PendingApproval queued).
/// 2. Bob emits an unsigned `approval.decision.v1` for Alice's hold.
/// 3. After a full sync cycle, the hold is still queued and the sentinel does
///    not exist — the forged decision had no effect.
///
/// Run via: `scripts/matrix_integration_test.sh`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_exec_held_forged_decision_ignored() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");
    let sentinel = cwd.join("forged-decision-must-not-run");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester_agent = bob.user_id().expect("bob user id").to_string();
    let alice_id = alice.user_id().expect("alice user id").to_owned();

    let room = create_public_room(&bob, "mx-agent exec forged-decision security test (306)").await;
    let room_id = room.room_id().to_owned();
    alice.join_room_by_id(&room_id).await.expect("alice joins");
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice sees power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester_agent.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register target agent");

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
requires_approval = true
"#,
            room = room_id.as_str(),
            agent = requester_agent,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };

    let invocation_id = format!("inv_306_forged_{}", std::process::id());
    let request_id = format!("req_306_forged_{}", std::process::id());
    save_session(&paths, &bob_session).expect("save requester session");
    let bob_room = bob.get_room(&room_id).expect("bob sees room");
    let content = build_signed_exec_request(
        signing.signing_key(),
        signing.key_id(),
        &invocation_id,
        &request_id,
        format!("nonce-306-forged-{}", std::process::id()),
        "2026-06-13T00:00:00Z",
        "2099-01-01T00:00:00Z",
        &ExecRequestOptions {
            target_agent: TARGET_AGENT.to_string(),
            requesting_agent: requester_agent.clone(),
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("touch {}", sentinel.to_string_lossy()),
            ],
            cwd: cwd.to_string_lossy().into_owned(),
            env: BTreeMap::new(),
            stdin: false,
            stream: false,
            pty: false,
            timeout_ms: 30_000,
            task_id: None,
        },
    )
    .expect("sign exec request");
    bob_room
        .send_raw(timeline::EXEC_REQUEST, content)
        .await
        .expect("send approval-required exec request");

    // Wait for the hold to be enqueued.
    let hold_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let pending = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
        if pending.iter().any(|p| p.request_id() == request_id) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < hold_deadline,
            "daemon should hold the approval-required exec within 60 s (issue #306)"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        !sentinel.exists(),
        "exec must not spawn while held pending approval (issue #306)"
    );

    // Bob sends a forged unsigned decision from his own Matrix account. His
    // sender identity is NOT Alice's local_user, so `handle_live_approval_decision`
    // drops the event at the `untrusted_sender` check without modifying the hold.
    bob_room
        .send_raw(
            timeline::APPROVAL_DECISION,
            json!({
                "request_id": request_id,
                "decision": DECISION_APPROVED,
                "approved_by": bob.user_id().expect("bob user id").as_str(),
                "created_at": "2026-06-13T00:00:00Z",
            }),
        )
        .await
        .expect("send forged unsigned decision from bob");

    // Give Alice's sync loop time to process the forged event (at least one full
    // sync cycle). The forged decision should be silently dropped.
    tokio::time::sleep(Duration::from_secs(10)).await;

    // The hold must still be queued — the forged decision had no effect.
    let pending_after = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
    assert!(
        pending_after.iter().any(|p| p.request_id() == request_id),
        "hold must remain queued after a forged decision from an untrusted sender (issue #306)"
    );
    assert!(
        !sentinel.exists(),
        "exec must not spawn after a forged decision — fail-closed (issue #306)"
    );

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");
}

/// Issue #306: a live exec hold whose approval window has expired is swept by
/// the scheduler and never runs.
///
/// `sweep_expired_live_holds` (called every scheduler pass) detects a live hold
/// whose persisted `expires_at` is in the past, emits `exec.rejected`
/// (`approval_expired`), removes the queue entry, and **never** spawns the
/// command — mirroring #291 for task-backed holds.
///
/// A task-backed hold (`held_request == None`) is intentionally skipped by
/// the sweep (its lifetime is the scheduler gate's responsibility). This test
/// uses a live hold (`held_request == Some(HeldRequest::Exec(...))`) to prove
/// the correct branch is taken.
///
/// The hold is pre-injected with `expires_at: "2020-01-01T00:00:00Z"` so the
/// first scheduler pass immediately finds an expired entry without waiting one
/// hour for APPROVAL_REQUEST_TTL to elapse.
///
/// Verifies:
/// 1. Pre-injected expired live hold is in the queue before scheduler start.
/// 2. Scheduler sweeps it within 60 s (queue entry removed).
/// 3. Sentinel file never created — the exec command never spawned.
///
/// Run via: `scripts/matrix_integration_test.sh`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_exec_held_expiry_never_runs() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");
    let sentinel = cwd.join("expiry-exec-must-not-run");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester_agent = bob.user_id().expect("bob user id").to_string();
    let alice_id = alice.user_id().expect("alice user id").to_owned();

    let room = create_public_room(&bob, "mx-agent exec hold expiry test (306)").await;
    let room_id = room.room_id().to_owned();
    alice.join_room_by_id(&room_id).await.expect("alice joins");
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice sees power levels");

    // Alice registers an agent so the scheduler runs a pass for this room and
    // calls sweep_expired_live_holds.
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register target agent");

    let signing = load_or_create_signing_key(&paths).expect("signing key");

    // Pre-populate the approval queue with an already-expired live exec hold.
    // The command would touch the sentinel if it ever ran; the expiry sweep
    // must not spawn it.
    let invocation_id = format!("inv_306_expiry_{}", std::process::id());
    let request_id = format!("req_306_expiry_{}", std::process::id());
    let mut pre_queue = ApprovalQueue::default();
    pre_queue.enqueue(PendingApproval {
        room_id: room_id.to_string(),
        request: ApprovalRequest {
            request_id: request_id.clone(),
            invocation_id: invocation_id.clone(),
            requester: requester_agent.clone(),
            target: TARGET_AGENT.to_string(),
            summary: format!(
                "Run touch sentinel (expiry test) in {}",
                cwd.to_string_lossy()
            ),
            risk: "medium".to_string(),
            expires_at: "2020-01-01T00:00:00Z".to_string(), // far in the past
            extra: Default::default(),
        },
        // Live hold: held_request carries the original exec. The expiry sweep
        // selects only holds where held_request.is_some() (task-backed holds
        // with held_request == None are left to the scheduler gate).
        held_request: Some(HeldRequest::Exec(ExecRequest {
            invocation_id: invocation_id.clone(),
            request_id: request_id.clone(),
            target_agent: TARGET_AGENT.to_string(),
            requesting_agent: requester_agent.clone(),
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("touch {}", sentinel.to_string_lossy()),
            ],
            cwd: cwd.to_string_lossy().into_owned(),
            env: Default::default(),
            stdin: false,
            stream: false,
            pty: false,
            timeout_ms: 30_000,
            task_id: None,
            created_at: "2020-01-01T00:00:00Z".to_string(),
            expires_at: "2020-01-01T00:00:00Z".to_string(),
            nonce: format!("nonce-306-expiry-{}", std::process::id()),
            idempotency_key: format!("exec:{invocation_id}"),
            signature: Signature {
                alg: "ed25519".to_string(),
                key_id: signing.key_id().to_string(),
                // Placeholder sig: the expiry path never verifies the held
                // request's own signature (the decision is already verified);
                // the command is rejected before any spawn.
                sig: "placeholder-not-verified-for-expiry-path".to_string(),
            },
            extra: Default::default(),
        })),
    });
    pre_queue.save(&paths).expect("save pre-expired live hold");

    // Confirm the hold is queued before the scheduler starts.
    let before = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
    assert!(
        before.iter().any(|p| p.request_id() == request_id),
        "pre-injected expired live hold must be in the queue before the scheduler starts (issue #306)"
    );
    assert!(
        !sentinel.exists(),
        "sentinel must not exist before the sweep"
    );

    // Start both the sync loop (provides the room handle) and the scheduler
    // loop (runs sweep_expired_live_holds every pass).
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };
    let scheduler = {
        let alice = alice.clone();
        let running = running.clone();
        std::thread::spawn(move || {
            run_scheduler_loop(
                alice,
                ExecSubscriberRegistry::new(),
                TaskDispatchMode::Local,
                running,
                Duration::from_secs(1),
            );
        })
    };

    // Wait for the scheduler to sweep the expired hold (queue entry removed).
    let sweep_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let remaining = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
        if !remaining.iter().any(|p| p.request_id() == request_id) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < sweep_deadline,
            "scheduler must sweep the expired live hold within 60 s (issue #306)"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // A 2 s grace period is enough — a spawned `sh -c touch …` finishes in
    // milliseconds; the expiry path must not spawn it at all.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !sentinel.exists(),
        "expired live exec hold must never spawn its command (issue #306)"
    );

    running.store(false, Ordering::SeqCst);
    scheduler.join().expect("scheduler thread joins");
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");
}

/// Decrypt-after-restart from the persistent crypto store (issue #260; issue
/// #240 "Stage 1").
///
/// Proves the durability property the persistent, device-keyed crypto store
/// exists for: a daemon that resumes as the **same** E2EE device decrypts a
/// message that was encrypted to it *while it was down*.
///
/// 1. Alice (device A) and Bob log in and restore; both drive a live `/sync`.
/// 2. Bob creates an encrypted room, Alice joins, and Bob sends message #1 —
///    Alice decrypts it, persisting the inbound Megolm session into device A's
///    SQLite store.
/// 3. **Restart**: Alice's sync task is aborted and her client dropped so no
///    in-memory crypto state survives, then Bob sends message #2 over the *same*
///    Megolm session while Alice is down.
/// 4. **Rebuild**: `restore_client` reopens the same device-id store and Alice
///    decrypts message #2 — proving the resumed device identity plus the
///    persisted Megolm session decrypt an event sent while the device was down.
///
/// Sync is driven via the **raw** matrix-sdk `Client::sync` rather than
/// [`run_matrix_sync`]: the daemon sync loop publishes its client into the
/// process-global active-client registry (`matrix.rs` `publish_active_client`),
/// and a published client is returned by the second `restore_client`, which would
/// reuse the in-memory client and defeat the rebuild-from-disk this test depends
/// on. Aborting the sync task and dropping the client releases the SQLite store
/// handle so the restart truly reopens it from disk.
///
/// Unlike the helper-only tests, this one needs the crypto store rooted at a
/// throwaway `MX_AGENT_DATA_DIR` (both `login_password` and `restore_client`
/// resolve the device-keyed store from that env var), so it sets the env var
/// rather than using `paths_in`.
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_decrypt_after_restart_from_persistent_store() {
    let _serial = enter_single_threaded_section();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    // The device-keyed crypto store lives under MX_AGENT_DATA_DIR, so it must be
    // set (not just `paths_in`) for the restart to rebuild from the same store.
    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");

    // Raw SDK sync for both (NOT run_matrix_sync — see the doc comment).
    let bob_sync = {
        let bob = bob.clone();
        tokio::spawn(async move {
            let _ = bob.sync(SyncSettings::default()).await;
        })
    };
    let alice_sync = {
        let alice = alice.clone();
        tokio::spawn(async move {
            let _ = alice.sync(SyncSettings::default()).await;
        })
    };

    // Encrypted room shared with device A so Bob shares the Megolm room key.
    let room = create_encrypted_room(&bob, "mx-agent decrypt-after-restart").await;
    let room_id = room.room_id().to_owned();
    let alice_room = alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins encrypted room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;

    // Message #1 (while up) establishes + persists the inbound Megolm session.
    let msg1 = "restart msg #1 (while up)";
    let msg1_id = room
        .send(RoomMessageEventContent::text_plain(msg1))
        .await
        .expect("bob sends msg #1")
        .response
        .event_id;
    let decrypted1 = decrypted_content(&alice_room, &msg1_id).await;
    assert_eq!(
        decrypted1.get("body").and_then(|b| b.as_str()),
        Some(msg1),
        "device A must decrypt the first message while up; got {decrypted1}"
    );

    // ---- Restart: tear down Alice's client so no in-memory crypto remains. ----
    alice_sync.abort();
    let _ = alice_sync.await; // ensure the sync task's client clone is dropped
    drop(alice_room);
    drop(alice);
    // Give the dropped client a moment to release its SQLite store handle.
    tokio::time::sleep(Duration::from_millis(500)).await;
    // The on-disk device-keyed crypto store must persist across the restart.
    let device_store = data_dir.join(&alice_session.device_id);
    assert!(
        device_store.exists(),
        "device-keyed crypto store {device_store:?} must persist across the restart"
    );

    // ---- While Alice is down: Bob sends msg #2 over the same Megolm session. ----
    let msg2 = "restart msg #2 (while down)";
    let msg2_id = room
        .send(RoomMessageEventContent::text_plain(msg2))
        .await
        .expect("bob sends msg #2")
        .response
        .event_id;

    // ---- Rebuild Alice from the same device-id store and decrypt msg #2. ----
    let alice2 = restore_client(&alice_session)
        .await
        .expect("alice restart restore from the persistent store");
    let alice2_sync = {
        let alice2 = alice2.clone();
        tokio::spawn(async move {
            let _ = alice2.sync(SyncSettings::default()).await;
        })
    };
    let alice2_room = alice2
        .join_room_by_id(&room_id)
        .await
        .expect("resumed device A sees the room");
    let decrypted2 = decrypted_content(&alice2_room, &msg2_id).await;
    assert_eq!(
        decrypted2.get("body").and_then(|b| b.as_str()),
        Some(msg2),
        "the resumed device A must decrypt a message sent while it was down; got {decrypted2}"
    );

    alice2_sync.abort();
    let _ = alice2_sync.await;
    bob_sync.abort();
    let _ = bob_sync.await;
    std::env::remove_var(ENV_DATA_DIR);
}

/// Key-backup restore across a re-provision (issue #260; issue #240 criterion
/// #5).
///
/// Proves that server-side key backup restores decryptability of
/// previously-encrypted history after a device is re-provisioned with an empty
/// crypto store — the round-trip the existing `live_recovery_enable_and_status`
/// test documented as a follow-up.
///
/// 1. **Device A**: log in, sync to `Healthy`, `bootstrap_cross_signing`, then
///    `enable_recovery`; capture the one-time recovery key via `Secret::expose`
///    (asserting `Debug` still redacts it). The key is held only in a local
///    `String` and never logged.
/// 2. **History**: Bob creates an encrypted room, device A joins and decrypts a
///    message (so device A holds the room key), and that room key is uploaded to
///    server-side backup (`wait_for_steady_state`).
/// 3. **Re-provision**: a second `login_password` for the same user mints
///    **device B** with an empty store; device B can fetch but **not** decrypt
///    the history (asserted before restore).
/// 4. **Restore**: `recover` with the recovery key re-imports the secrets
///    (cross-signing + the backup decryption key) and enables the backup, then
///    the room's keys are pulled down from the server-side backup
///    (`download_room_keys_for_room`) so device B decrypts the
///    previously-encrypted history.
///
/// Uses a fresh-per-run `MX_AGENT_TEST_BACKUP_USER` (pristine cross-signing +
/// clean backup version), falling back to the shared user when unset (hermetic
/// only against a freshly-reset homeserver — see the recovery test's note).
///
/// Homeserver requirement: this exercises the full `/room_keys` upload +
/// re-import round trip. If a Conduit-family homeserver does not fully support
/// server-side key backup, `recover` / the final decrypt will fail loud, which is
/// the intended signal that the homeserver lacks the capability.
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_key_backup_restore_across_reprovision() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    // Fresh per-run user for pristine cross-signing + a clean backup version;
    // fall back to the shared user so a bare `cargo test` still runs.
    let alice_user = std::env::var("MX_AGENT_TEST_BACKUP_USER")
        .unwrap_or_else(|_| required_env("MX_AGENT_TEST_USER"));
    let alice_pass = std::env::var("MX_AGENT_TEST_BACKUP_PASSWORD")
        .unwrap_or_else(|_| required_env("MX_AGENT_TEST_PASSWORD"));
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };

    // ---- Device A: login, sync to Healthy, bootstrap cross-signing, backup. ----
    let device_a_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("device A login");
    let device_a = restore_client(&device_a_session)
        .await
        .expect("device A restore");
    let running = Arc::new(AtomicBool::new(true));
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let a_sync = {
        let device_a = device_a.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&device_a, &paths, health, BackoffConfig::default(), running).await
        })
    };
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            {
                let h = health.lock().unwrap();
                if h.state == SyncState::Healthy && h.total_syncs > 0 {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("device A sync must reach Healthy before enabling recovery");

    let cs = mx_agent_daemon::bootstrap_cross_signing(&device_a)
        .await
        .expect("bootstrap cross-signing on device A");
    assert!(
        cs.has_master && cs.complete,
        "cross-signing identity must be complete on device A; got {cs:?}"
    );
    let enabled = mx_agent_daemon::enable_recovery(&device_a)
        .await
        .expect("enable recovery on device A");
    assert_eq!(
        enabled.status.state, "enabled",
        "recovery must be enabled on device A; got {:?}",
        enabled.status
    );
    assert!(
        enabled.status.backup_enabled,
        "key backup must be enabled on device A; got {:?}",
        enabled.status
    );
    // Read the one-time recovery key into a local String. NEVER log it.
    let recovery_key = enabled.recovery_key.expose().to_string();
    // The Secret must still redact in Debug — the exposed value must not leak.
    assert!(
        format!("{:?}", enabled.recovery_key).contains("***redacted***"),
        "recovery key must remain redacted in Debug output"
    );

    // ---- Establish backed-up history: Bob's encrypted message, decrypted by A. ----
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let bob_sync = {
        let bob = bob.clone();
        tokio::spawn(async move {
            let _ = bob.sync(SyncSettings::default()).await;
        })
    };

    let room = create_encrypted_room(&bob, "mx-agent key-backup restore").await;
    let room_id = room.room_id().to_owned();
    let a_room = device_a
        .join_room_by_id(&room_id)
        .await
        .expect("device A joins encrypted room");
    let a_id = device_a.user_id().expect("device A user id").to_owned();
    wait_for_joined_member(&room, &a_id).await;

    let history = "backed-up history line";
    let history_id = room
        .send(RoomMessageEventContent::text_plain(history))
        .await
        .expect("bob sends history")
        .response
        .event_id;
    let pre = decrypted_content(&a_room, &history_id).await;
    assert_eq!(
        pre.get("body").and_then(|b| b.as_str()),
        Some(history),
        "device A must decrypt the history before backup; got {pre}"
    );

    // Upload device A's room keys to server-side backup and wait until the
    // upload reaches steady state. Assert the outcome (rather than discarding it)
    // so an incomplete server-side backup upload fails loud here with a clear
    // signal, instead of surfacing later as a confusing decrypt timeout on
    // device B (issue #260 review finding).
    tokio::time::timeout(Duration::from_secs(60), async {
        device_a
            .encryption()
            .backups()
            .wait_for_steady_state()
            .await
    })
    .await
    .expect("server-side key-backup upload did not reach steady state within 60s")
    .expect("server-side key-backup upload failed");

    // ---- Re-provision: log in again as the SAME user → device B, empty store. ----
    let device_b_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("device B login (re-provision)");
    assert_ne!(
        device_b_session.device_id, device_a_session.device_id,
        "re-provision must mint a new device id with a fresh, empty crypto store"
    );
    let device_b = restore_client(&device_b_session)
        .await
        .expect("device B restore");
    let b_sync = {
        let device_b = device_b.clone();
        tokio::spawn(async move {
            let _ = device_b.sync(SyncSettings::default()).await;
        })
    };
    let b_room = device_b
        .join_room_by_id(&room_id)
        .await
        .expect("device B sees the room (same user, already a member)");

    // Prove the history is NOT decryptable on the empty store before restore.
    let undecryptable = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(ev) = b_room.event(&history_id, None).await {
                if ev.encryption_info().is_none() {
                    return true; // fetched, but not decrypted
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        undecryptable,
        "device B (empty store) must NOT decrypt the history before key-backup restore"
    );

    // ---- Restore: re-import keys from server-side backup with the recovery key. ----
    let restored = mx_agent_daemon::recover(&device_b, &recovery_key)
        .await
        .expect("device B recovers keys from server-side backup");
    assert_eq!(
        restored.state, "enabled",
        "recovery status after recover must be 'enabled'; got {restored:?}"
    );
    assert!(
        restored.backup_enabled,
        "key backup must be enabled after recover; got {restored:?}"
    );

    // `recover` re-imports the secrets (cross-signing + the backup decryption
    // key) and enables the backup, but it does not eagerly pull the room keys
    // down from the server-side backup: in production that happens lazily on the
    // daemon's long-running sync via the SDK's download-after-decryption-failure
    // strategy. This test decrypts a single historical event synchronously, so
    // pull the room's keys from the backup explicitly to prove the restore
    // round-trip deterministically instead of racing the background download.
    device_b
        .encryption()
        .backups()
        .download_room_keys_for_room(&room_id)
        .await
        .expect("device B downloads the room's keys from the server-side backup");

    // ---- Device B can now decrypt the previously-encrypted history. ----
    let post = decrypted_content(&b_room, &history_id).await;
    assert_eq!(
        post.get("body").and_then(|b| b.as_str()),
        Some(history),
        "device B must decrypt the history after restore; got {post}"
    );

    running.store(false, Ordering::SeqCst);
    let _ = a_sync.await.expect("device A sync joins");
    b_sync.abort();
    let _ = b_sync.await;
    bob_sync.abort();
    let _ = bob_sync.await;
    std::env::remove_var(ENV_DATA_DIR);
}

/// Drive the **responder** side of an interactive SAS through the raw
/// matrix-sdk verification API (issue #260).
///
/// The daemon exposes only the requester helpers (`start_sas`/`advance_sas`/…);
/// the requester's flow id is an internal ULID, not the SDK transaction id, so
/// the peer cannot look the flow up through the daemon. The responder therefore
/// learns the SDK flow id from the captured incoming `m.key.verification.request`
/// (`flow_id_slot`), resolves and accepts the request, accepts the SAS once the
/// requester starts it, and confirms once the short-auth string is presentable.
/// In the test there is no human, so it confirms unconditionally — both daemons
/// compute the same SAS.
async fn drive_sas_responder(
    responder: &Client,
    requester: &UserId,
    flow_id_slot: Arc<Mutex<Option<String>>>,
) {
    // 1) Learn the SDK flow id from the captured incoming request.
    let flow_id = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(id) = flow_id_slot.lock().unwrap().clone() {
                return id;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("responder must observe the incoming verification request");

    // 2) Resolve and accept the verification request.
    let request = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(req) = responder
                .encryption()
                .get_verification_request(requester, &flow_id)
                .await
            {
                return req;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("responder must resolve the verification request");
    request
        .accept()
        .await
        .expect("responder accepts the verification request");

    // 3) Once the requester starts the SAS, obtain and accept it.
    let sas = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(sas) = responder
                .encryption()
                .get_verification(requester, &flow_id)
                .await
                .and_then(|v| v.sas())
            {
                return sas;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("responder must obtain the SAS once the requester starts it");
    // The requester started the flow; accept it on the responder side. Ignore an
    // error in case the SDK already auto-accepted.
    let _ = sas.accept().await;

    // 4) Confirm once the short-auth string is presentable; drive to done.
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut confirmed = false;
        loop {
            assert!(!sas.is_cancelled(), "responder SAS was cancelled");
            if sas.is_done() {
                return;
            }
            if !confirmed && sas.can_be_presented() {
                sas.confirm().await.expect("responder confirms the SAS");
                confirmed = true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("responder SAS must reach done");
}

/// Full two-daemon interactive SAS happy path (issue #260).
///
/// Drives the emoji/SAS request → accept → present → confirm flow between two
/// independent daemons to a mutual `confirmed`, then asserts
/// `sender_verified == Some(true)` on **both** sides — closing the gap left by
/// `live_device_manual_verify_and_sender_verified`, which only exercises the
/// out-of-band `manual_verify` path.
///
/// The requester (Alice) is driven through the daemon helpers
/// (`start_sas`/`advance_sas`/`confirm_sas`); the responder (Bob) is driven
/// through the raw matrix-sdk API by [`drive_sas_responder`] (no daemon
/// responder helper exists — see its doc comment). Both run live `/sync` loops so
/// the to-device verification traffic flows.
///
/// Uses fresh-per-run `MX_AGENT_TEST_SAS_USER`/`_USER2` so each peer has exactly
/// **one** device — the all-devices `sender_verified == Some(true)` assertion
/// would otherwise be defeated by devices accumulated by other tests'
/// `login_password` calls on the shared users. Falls back to the shared users
/// when unset (hermetic only against a freshly-reset homeserver).
///
/// This validates the **transport** verification signal only; per architecture
/// §1.2 device verification stays advisory and never grants execution authority
/// (signing + trust + policy remain the gate).
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_two_daemon_sas_confirms_and_verifies() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    // Fresh per-run users so each peer has exactly one device (see doc comment).
    let alice_user = std::env::var("MX_AGENT_TEST_SAS_USER")
        .unwrap_or_else(|_| required_env("MX_AGENT_TEST_USER"));
    let alice_pass = std::env::var("MX_AGENT_TEST_SAS_PASSWORD")
        .unwrap_or_else(|_| required_env("MX_AGENT_TEST_PASSWORD"));
    let bob_user = std::env::var("MX_AGENT_TEST_SAS_USER2")
        .unwrap_or_else(|_| required_env("MX_AGENT_TEST_USER2"));
    let bob_pass = std::env::var("MX_AGENT_TEST_SAS_PASSWORD2")
        .unwrap_or_else(|_| required_env("MX_AGENT_TEST_PASSWORD2"));

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");

    let alice_id = alice.user_id().expect("alice user id").to_owned();
    let bob_id = bob.user_id().expect("bob user id").to_owned();

    // Both need live crypto sync for to-device verification traffic.
    let alice_sync = {
        let alice = alice.clone();
        tokio::spawn(async move {
            let _ = alice.sync(SyncSettings::default()).await;
        })
    };
    let bob_sync = {
        let bob = bob.clone();
        tokio::spawn(async move {
            let _ = bob.sync(SyncSettings::default()).await;
        })
    };

    // A shared encrypted room makes each side download the other's device keys.
    let room = create_encrypted_room(&bob, "mx-agent two-daemon SAS").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins encrypted room");
    wait_for_joined_member(&room, &alice_id).await;

    // Wait until Alice sees Bob's (single) device, and Bob sees Alice's.
    let bob_device = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Ok(devs) = mx_agent_daemon::list_devices(&alice, bob_id.as_str()).await {
                if let Some(d) = devs.into_iter().next() {
                    return d;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("alice must see bob's device");
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Ok(devs) = mx_agent_daemon::list_devices(&bob, alice_id.as_str()).await {
                if !devs.is_empty() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("bob must see alice's device");

    // Pre-assert: neither side considers the other verified yet.
    assert_ne!(
        mx_agent_daemon::sender_verified(&alice, bob_id.as_str()).await,
        Some(true),
        "bob must not be verified by alice before SAS"
    );
    assert_ne!(
        mx_agent_daemon::sender_verified(&bob, alice_id.as_str()).await,
        Some(true),
        "alice must not be verified by bob before SAS"
    );

    // Capture the incoming verification request's SDK flow id on Bob BEFORE the
    // requester sends it, so the responder can resolve the SDK flow.
    let flow_id_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    {
        let slot = flow_id_slot.clone();
        let requester_uid = alice_id.clone();
        bob.add_event_handler(move |ev: ToDeviceKeyVerificationRequestEvent| {
            let slot = slot.clone();
            let requester_uid = requester_uid.clone();
            async move {
                if ev.sender == requester_uid {
                    let mut guard = slot.lock().unwrap();
                    if guard.is_none() {
                        *guard = Some(ev.content.transaction_id.to_string());
                    }
                }
            }
        });
    }

    // Requester (Alice) starts the SAS against Bob's device.
    let flow_id_a = mx_agent_daemon::start_sas(&alice, bob_id.as_str(), &bob_device.device_id)
        .await
        .expect("alice starts the SAS");

    // Drive the responder concurrently with the requester.
    let responder = {
        let bob = bob.clone();
        let requester_uid = alice_id.clone();
        let slot = flow_id_slot.clone();
        tokio::spawn(async move { drive_sas_responder(&bob, &requester_uid, slot).await })
    };

    // Requester loop: advance to Ready, confirm once, advance to Done.
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut confirmed = false;
        loop {
            match mx_agent_daemon::advance_sas(&flow_id_a)
                .await
                .expect("advance the SAS")
            {
                SasAdvance::Done => return,
                SasAdvance::Cancelled => panic!("requester SAS was cancelled"),
                SasAdvance::Ready { .. } => {
                    if !confirmed {
                        mx_agent_daemon::confirm_sas(&flow_id_a)
                            .await
                            .expect("requester confirms the SAS");
                        confirmed = true;
                    }
                }
                SasAdvance::Pending | SasAdvance::Negotiating => {}
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("requester SAS must reach done");

    responder.await.expect("responder task joins");

    // ---- Both-sides assertion: each side now considers the other verified. ----
    let both_verified = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if mx_agent_daemon::sender_verified(&alice, bob_id.as_str()).await == Some(true)
                && mx_agent_daemon::sender_verified(&bob, alice_id.as_str()).await == Some(true)
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        both_verified,
        "after a mutual SAS confirm, both sides must report sender_verified == Some(true)"
    );

    // Belt-and-suspenders: the specific peer device shows verified via list_devices.
    let alice_view = mx_agent_daemon::list_devices(&alice, bob_id.as_str())
        .await
        .expect("alice lists bob's devices");
    assert!(
        alice_view
            .iter()
            .any(|d| d.device_id == bob_device.device_id && d.verified),
        "bob's verified device must show verified in alice's device list; got {alice_view:?}"
    );
    let bob_view = mx_agent_daemon::list_devices(&bob, alice_id.as_str())
        .await
        .expect("bob lists alice's devices");
    assert!(
        !bob_view.is_empty() && bob_view.iter().all(|d| d.verified),
        "alice's device(s) must show verified in bob's device list; got {bob_view:?}"
    );

    mx_agent_daemon::forget_sas(&flow_id_a);
    alice_sync.abort();
    let _ = alice_sync.await;
    bob_sync.abort();
    let _ = bob_sync.await;
    std::env::remove_var(ENV_DATA_DIR);
}

/// A non-creator daemon can register and heartbeat in a workspace room provisioned
/// by production code — issue #301.
///
/// Contract under test: `build_create_room_request` emits a
/// `power_level_content_override` that pins every `com.mxagent.*` state type to
/// power level 50 and raises `state_default` to 100 (creator-only for native room
/// state). A non-creator daemon elevated to PL 50 via `grant_workspace` can then
/// write `com.mxagent.agent.v1` (register) and `com.mxagent.agent.v1` (heartbeat
/// state refresh) without hitting M_FORBIDDEN.
///
/// **No manual `m.room.power_levels` grant is made in this test** — the room's
/// PL structure comes entirely from `create_workspace`. The only grant is the
/// application-level `grant_workspace` that the creator is expected to issue in
/// production.
///
/// Security: power levels are a Matrix transport/integrity property only.
/// Granting PL 50 never implies execution permission; the Ed25519 signature +
/// local trust + deny-by-default policy gate remains authoritative (architecture
/// §14).
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn workspace_power_levels_non_creator_daemon_registers_and_heartbeats() {
    let _serial = enter_single_threaded_section();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    // Each daemon gets its own data dir so signing identities don't collide.
    let base = throwaway_data_dir();
    let alice_dir = base.join("alice");
    let bob_dir = base.join("bob");
    paths_in(alice_dir.clone())
        .ensure_data_dir()
        .expect("create alice data dir");
    paths_in(bob_dir.clone())
        .ensure_data_dir()
        .expect("create bob data dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session)
        .await
        .expect("alice session restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session)
        .await
        .expect("bob session restore");

    // ── Step 1: Alice (creator) creates a workspace via production code ──────
    //
    // The public visibility lets Bob join without an invite. No manual
    // `m.room.power_levels` grant is issued here; all PL structure comes from
    // the `power_level_content_override` that `build_create_room_request` sets.
    let ws_info = create_workspace(
        &alice,
        &CreateWorkspaceOptions {
            name: Some("it-pl-non-creator-301".to_string()),
            topic: None,
            alias: None,
            visibility: WorkspaceVisibility::Public,
            e2ee: false,
        },
    )
    .await
    .expect("alice creates workspace via production code");

    let ws_room_id: OwnedRoomId = ws_info.room_id.parse().expect("valid workspace room id");

    // ── Step 2: Bob (non-creator) joins the workspace ────────────────────────
    bob.join_room_by_id(&ws_room_id)
        .await
        .expect("bob joins workspace");

    let alice_room = alice
        .get_room(&ws_room_id)
        .expect("alice sees her workspace room");

    let bob_id = bob.user_id().expect("bob user id").to_owned();
    wait_for_joined_member(&alice_room, &bob_id).await;

    // ── Step 3: Alice grants Bob the workspace agent power level ─────────────
    //
    // In production the creator runs `mx-agent workspace grant` after inviting
    // or after the joiner is visible. The grant issues a homeserver
    // `m.room.power_levels` update that elevates Bob to PL 50.
    grant_workspace(
        &alice,
        &GrantWorkspaceOptions {
            room: ws_room_id.to_string(),
            user: bob_id.to_string(),
            level: None, // defaults to WORKSPACE_AGENT_PL (50)
        },
    )
    .await
    .expect("alice grants bob workspace agent PL");

    // Sync Bob's client so it observes the updated power levels.
    bob.sync_once(SyncSettings::default())
        .await
        .expect("bob syncs updated power levels");

    let bob_room = bob.get_room(&ws_room_id).expect("bob sees workspace room");

    // ── Step 4: Bob registers an agent — must NOT produce M_FORBIDDEN ────────
    //
    // `register_agent` writes a `com.mxagent.agent.v1` state event, which
    // requires PL >= 50. Under production room setup (PL override from
    // `build_create_room_request`) Bob at PL 50 is allowed.
    std::env::set_var(ENV_DATA_DIR, &bob_dir);
    let bob_agent_id = format!(
        "bob-pl-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: ws_room_id.to_string(),
            agent_id: Some(bob_agent_id.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["shell".to_string()],
            tools: vec![],
            cwd: "/tmp".to_string(),
            project_id: "mx-agent-pl-301-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect(
        "non-creator daemon at PL 50 must be able to register (write com.mxagent.agent.v1 state) \
         without M_FORBIDDEN — issue #301: room was created by production code with \
         power_level_content_override",
    );

    // ── Step 5: Bob emits a heartbeat — must NOT produce M_FORBIDDEN ─────────
    //
    // `emit_heartbeat` may refresh the durable `com.mxagent.agent.v1` state
    // (another PL 50-gated write). A zero `state_refresh` forces the state
    // path; the timeline heartbeat event (PL 0, always sendable) is the fast path.
    let hb_cfg = HeartbeatConfig {
        state_refresh: Duration::ZERO,
        ..HeartbeatConfig::default()
    };
    emit_heartbeat(&bob_room, &bob_agent_id, "active", &hb_cfg, 0)
        .await
        .expect(
            "non-creator daemon at PL 50 must be able to emit a heartbeat (write \
             com.mxagent.agent.v1 durable state) without M_FORBIDDEN — issue #301",
        );

    // ── Step 6: confirm the registered agent is visible ──────────────────────
    //
    // Alice discovers Bob's agent via a standard sync. If the state write
    // succeeded above, the agent listing must include Bob's agent ID.
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice syncs to observe bob's registration");
    let agents = list_agents(
        &alice,
        &ListAgentsOptions {
            room: ws_room_id.to_string(),
            capabilities: vec![],
        },
    )
    .await
    .expect("alice lists agents");
    assert!(
        agents.iter().any(|a| a.agent_id == bob_agent_id),
        "alice must discover bob's registered agent after production-code workspace grant; \
         agents found: {agents:?} — issue #301"
    );

    std::env::remove_var(ENV_DATA_DIR);
}

/// A plain workspace member (no PL grant) cannot overwrite another agent's state —
/// issue #301 integrity guarantee.
///
/// Contract under test: with `state_default` raised to 100 and each
/// `com.mxagent.*` type pinned to 50 in `power_level_content_override`, a member
/// at PL 0 (no grant) is refused on any `com.mxagent.*` state write. The daemon
/// surfaces this as [`WorkspaceError::WorkspaceForbidden`] with a guided message
/// that names the room, event type, and required power level but contains no
/// secrets (tokens, signatures).
///
/// Security: this guards state integrity / DoS. Without narrow per-type PLs a
/// plain member could overwrite any agent's published state. The test confirms the
/// refusal without weakening the execution gate (which is Ed25519 + trust, not
/// room PLs).
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn workspace_plain_member_cannot_overwrite_agent_state() {
    let _serial = enter_single_threaded_section();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let base = throwaway_data_dir();
    let alice_dir = base.join("alice");
    let bob_dir = base.join("bob");
    paths_in(alice_dir.clone())
        .ensure_data_dir()
        .expect("create alice data dir");
    paths_in(bob_dir.clone())
        .ensure_data_dir()
        .expect("create bob data dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session)
        .await
        .expect("alice session restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session)
        .await
        .expect("bob session restore");

    // Alice creates a workspace with production power-level provisioning.
    let ws_info = create_workspace(
        &alice,
        &CreateWorkspaceOptions {
            name: Some("it-pl-integrity-301".to_string()),
            topic: None,
            alias: None,
            visibility: WorkspaceVisibility::Public,
            e2ee: false,
        },
    )
    .await
    .expect("alice creates workspace");

    let ws_room_id: OwnedRoomId = ws_info.room_id.parse().expect("valid workspace room id");

    // Alice registers her agent (PL 100 as creator — always succeeds).
    std::env::set_var(ENV_DATA_DIR, &alice_dir);
    let alice_agent_id = format!(
        "alice-integrity-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: ws_room_id.to_string(),
            agent_id: Some(alice_agent_id.clone()),
            kind: "claude-code".to_string(),
            capabilities: vec!["plan".to_string()],
            tools: vec![],
            cwd: "/tmp".to_string(),
            project_id: "mx-agent-pl-301-integrity".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("alice registers her agent as workspace creator");
    std::env::remove_var(ENV_DATA_DIR);

    // Bob joins the workspace but is NOT granted any power level.
    bob.join_room_by_id(&ws_room_id)
        .await
        .expect("bob joins workspace");

    let alice_room = alice
        .get_room(&ws_room_id)
        .expect("alice sees her workspace room");
    let bob_id = bob.user_id().expect("bob user id").to_owned();
    wait_for_joined_member(&alice_room, &bob_id).await;

    bob.sync_once(SyncSettings::default())
        .await
        .expect("bob syncs to see room state");

    // Bob (PL 0, no grant) attempts to register an agent — this writes
    // `com.mxagent.agent.v1`, which requires PL >= 50 under the workspace PL
    // override. The attempt must produce WorkspaceError::WorkspaceForbidden.
    std::env::set_var(ENV_DATA_DIR, &bob_dir);
    let result = register_agent(
        &bob,
        &RegisterAgentOptions {
            room: ws_room_id.to_string(),
            agent_id: Some(alice_agent_id.clone()), // attempt to overwrite alice's state key
            kind: "attacker".to_string(),
            capabilities: vec![],
            tools: vec![],
            cwd: "/tmp".to_string(),
            project_id: "mx-agent-pl-301-integrity".to_string(),
            max_invocations: 1,
        },
    )
    .await;
    std::env::remove_var(ENV_DATA_DIR);

    match result {
        Err(WorkspaceError::WorkspaceForbidden {
            ref room_id,
            ref event_type,
            required_pl,
        }) => {
            assert_eq!(
                room_id,
                ws_room_id.as_str(),
                "WorkspaceForbidden must name the correct room"
            );
            assert!(
                !event_type.is_empty(),
                "WorkspaceForbidden must name the refused event type"
            );
            assert_eq!(
                required_pl, WORKSPACE_AGENT_PL,
                "WorkspaceForbidden must report the correct required power level"
            );
            // The guided error message must not expose secrets. Check the
            // Display output contains only non-secret metadata.
            let msg = format!("{}", result.unwrap_err());
            assert!(
                !msg.contains("token") && !msg.contains("signature"),
                "WorkspaceForbidden message must not contain secrets; got: {msg}"
            );
            assert!(
                msg.contains(ws_room_id.as_str()),
                "WorkspaceForbidden message must name the room; got: {msg}"
            );
        }
        Err(other) => panic!(
            "expected WorkspaceError::WorkspaceForbidden for plain member state write, got: {other:?} \
             — issue #301: production PL override should block PL-0 members from writing \
             com.mxagent.* state"
        ),
        Ok(_) => panic!(
            "plain member at PL 0 must NOT be able to overwrite another agent's \
             com.mxagent.agent.v1 state — issue #301 integrity guarantee: the workspace \
             power_level_content_override must block this write"
        ),
    }
}

/// Result-plane forge rejection: a second room member cannot resolve an
/// in-flight exec invocation with a forged `exec.finished` or inject output
/// via a forged `stream.chunk` (issue #304).
///
/// Security invariant under test: `ExecSubscriberRegistry::subscribe` pins every
/// subscription to the executing agent's Matrix user id (resolved from
/// `AgentState.matrix_user_id` before the request is sent). `publish_forwarded`
/// passes `meta.sender` into `ExecSubscriberRegistry::publish`, which delivers
/// the event only when `sender == expected_sender`. A forged result/stream event
/// from any other room member is counted as `filtered` and never reaches the
/// waiting IPC consumer — room membership is not execution permission
/// (architecture §1.2, §13). The test exercises this gate for both:
/// - **fake exit status** (`exec.finished` from a non-executing member)
/// - **injected output** (`stream.chunk` from a non-executing member)
///
/// This test exercises the full live path so that Matrix SDK event delivery,
/// the `/sync` routing loop, and the registry sender-pin gate are all proven
/// together across both event types (the unit-level coverage lives in
/// `exec_subscribers::tests`).
///
/// Setup:
/// - Alice is the **executor** (TARGET_AGENT): runs the target command and emits
///   the real `exec.finished`.
/// - Bob is both the **requester** (sends the signed exec request) and the
///   **adversarial forger**: immediately after sending the request, Bob publishes
///   a `com.mxagent.exec.finished.v1` carrying the distinctive fake exit code 42,
///   and a `com.mxagent.stream.chunk.v1` with the injected payload `FORGED_CHUNK_OUTPUT_304`.
///
/// Expected outcome:
/// - Bob's forged `exec.finished` (`sender = bob_id ≠ alice_id`) is filtered by
///   the sender-pin gate and never delivered to the subscription.
/// - Bob's forged `stream.chunk` is likewise filtered; the injected payload never
///   appears in the received output.
/// - Alice's real result (`sender = alice_id == expected_sender`) is eventually
///   delivered with exit code 77.
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_result_plane_forge_is_rejected() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();

    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester_agent = bob.user_id().expect("bob user id").to_string();
    let alice_id = alice.user_id().expect("alice user id").to_owned();

    let room = create_public_room(&bob, "mx-agent result-plane forge test").await;
    let room_id = room.room_id().to_owned();
    alice.join_room_by_id(&room_id).await.expect("alice joins");
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    for (client, agent_id) in [
        (&bob, requester_agent.clone()),
        (&alice, TARGET_AGENT.to_string()),
    ] {
        register_agent(
            client,
            &RegisterAgentOptions {
                room: room_id.to_string(),
                agent_id: Some(agent_id),
                kind: "pi".to_string(),
                capabilities: vec!["exec".to_string()],
                tools: vec![],
                cwd: cwd.to_string_lossy().into_owned(),
                project_id: "mx-agent-it".to_string(),
                max_invocations: 1,
            },
        )
        .await
        .expect("register agent");
    }

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
"#,
            room = room_id.as_str(),
            agent = requester_agent,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    let subscribers = ExecSubscriberRegistry::new();
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &alice,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };
    let bob_sync_paths = paths_in(data_dir.join("bob-sync"));
    bob_sync_paths.ensure_data_dir().expect("bob sync dir");
    let bob_sync = {
        let bob = bob.clone();
        let paths = bob_sync_paths.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &bob,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };

    // Subscribe pinned to alice_id (the executor). Any event whose sender is not
    // alice's Matrix user id is counted as filtered and never delivered here.
    let invocation_id = format!("inv_forge_{}", std::process::id());
    let mut subscription = subscribers.subscribe(
        ExecSubscriptionKey::Invocation(invocation_id.clone()),
        alice_id.to_string(),
    );

    // Build and send a signed exec request. The command sleeps for 1 s then
    // exits with code 77, giving the forger time to inject his fake result first.
    let options = ExecRequestOptions {
        target_agent: TARGET_AGENT.to_string(),
        requesting_agent: requester_agent.clone(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            "sleep 1; exit 77".to_string(),
        ],
        cwd: cwd.to_string_lossy().into_owned(),
        env: Default::default(),
        stdin: false,
        stream: true,
        pty: false,
        timeout_ms: 600_000,
        task_id: None,
    };
    let exec_content = build_signed_exec_request(
        signing.signing_key(),
        signing.key_id(),
        &invocation_id,
        format!("req_forge_{}", std::process::id()),
        format!("forge-nonce-{}", std::process::id()),
        "2026-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        &options,
    )
    .expect("sign exec request");

    // Bob's view of the room (for sending both the legitimate request and the
    // adversarial forge).
    let bob_room = bob.get_room(&room_id).expect("bob has the room");

    // Step 1 – send the legitimate signed exec request.
    bob_room
        .send_raw(timeline::EXEC_REQUEST, exec_content)
        .await
        .expect("send signed exec request");

    // Step 2 – adversarial forge: Bob immediately publishes a raw
    // `exec.finished` carrying the distinctive fake exit code 42. Bob's Matrix
    // sender (bob_id) does not equal the expected_sender (alice_id), so the
    // daemon's sender-pin gate must drop it before the subscription sees it.
    bob_room
        .send_raw(
            timeline::EXEC_FINISHED,
            json!({
                "invocation_id": invocation_id,
                "exit_code": 42,
                "signal": null,
                "duration_ms": 1,
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "truncated": false,
                "artifact_mxc": null
            }),
        )
        .await
        .expect("bob publishes forged exec.finished (exit code 42)");

    // Step 3 – adversarial output injection: Bob also publishes a raw
    // `stream.chunk` carrying distinctive content. The same sender-pin gate
    // covers all forwarded result/stream events; Bob's chunk must be filtered
    // before it reaches the subscription, so the injected payload never
    // appears in the output received by the waiting consumer (issue #304).
    const FORGED_CHUNK: &str = "FORGED_CHUNK_OUTPUT_304";
    bob_room
        .send_raw(
            timeline::STREAM_CHUNK,
            json!({
                "invocation_id": invocation_id,
                "stream": "stdout",
                "seq": 0,
                "encoding": "utf-8",
                "data": FORGED_CHUNK,
                "eof": false,
                "compressed": false,
                "sha256": null,
                "timestamp": "2026-01-01T00:00:00Z"
            }),
        )
        .await
        .expect("bob publishes forged stream.chunk");

    // Collect frames until ExecFinished arrives or the deadline expires.
    // Also accumulate StreamChunk data so forged output injection can be
    // detected: any chunk whose data contains FORGED_CHUNK was delivered by
    // the subscription, meaning the sender-pin gate failed for stream events.
    let mut seen_exit: Option<Option<i32>> = None;
    let mut received_chunk_data: Vec<String> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        match tokio::time::timeout(Duration::from_secs(5), subscription.recv()).await {
            Ok(Some(ForwardedExecEvent::ExecFinished(finished))) => {
                seen_exit = Some(finished.exit_code);
                break;
            }
            Ok(Some(ForwardedExecEvent::ExecRejected(rejected))) => {
                panic!(
                    "exec request was rejected by alice's daemon (policy/trust error): {:?}; \
                     check that policy.toml and trust store are set up correctly",
                    rejected.reason
                );
            }
            Ok(Some(ForwardedExecEvent::StreamChunk(chunk))) => {
                received_chunk_data.push(chunk.data.clone());
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {}
        }
    }

    running.store(false, Ordering::SeqCst);
    let _ = alice_sync.await.expect("alice sync task joins");
    let _ = bob_sync.await.expect("bob sync task joins");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");

    let exit_code = seen_exit.expect(
        "live exec invocation must deliver an ExecFinished frame within the 30 s deadline; \
         check alice's daemon logs for exec execution or policy rejection",
    );
    // Primary security assertion: the forged result (exit 42) must never have
    // been delivered. If sender-pinning were broken, Bob's forge would arrive
    // first (it was sent before alice's real result) and the assertion below
    // would catch it.
    assert_ne!(
        exit_code,
        Some(42),
        "forged exec.finished (exit 42) from a non-executing room member must not be \
         delivered to the waiting subscriber — sender-pin gate is broken (issue #304)"
    );
    // Confirm the legitimate executor's real exit code was received.
    assert_eq!(
        exit_code,
        Some(77),
        "the legitimate executor (alice) must deliver exit code 77 after the sender-pin \
         gate drops the forged event; got {exit_code:?}"
    );
    // Secondary security assertion: the injected stream chunk from Bob must
    // never have been delivered. The subscription is pinned to alice_id;
    // Bob's `stream.chunk` carries bob_id as sender, so the sender-pin gate
    // in `publish_forwarded` must have dropped it silently. A mismatch here
    // means the gate is broken for the output-injection attack vector.
    let forged_chunk_delivered = received_chunk_data.iter().any(|d| d.contains(FORGED_CHUNK));
    assert!(
        !forged_chunk_delivered,
        "forged stream.chunk from a non-executing room member must not be delivered \
         to the waiting subscriber — sender-pin gate is broken for stream.chunk (issue #304); \
         received chunks: {received_chunk_data:?}"
    );
}

/// Live trust-store anchor: a decision signed by a key published in
/// `com.mxagent.agent.v1` room state but absent from the local trust store is
/// rejected with `untrusted_key` and the held task is never released (issue #309).
///
/// The attack scenario: an adversary with room-state write access publishes a
/// fake `com.mxagent.agent.v1` event carrying their own Ed25519 key, then sends
/// a signed `approved` decision. Before #309 the verifying-key lookup used
/// room-published state as the sole anchor, so the fake key would resolve. After
/// #309 the trust store is also consulted: a key not in the operator's local store
/// is rejected regardless of what is in room state.
///
/// Steps:
/// 1. A throwaway Ed25519 key is created and published as room state under a fake
///    agent entry, but is NOT added to Alice's trust store.
/// 2. Bob creates a `requires_approval` task; the scheduler holds it fail-closed.
/// 3. Alice (the daemon's own Matrix user) publishes a decision signed with the
///    throwaway key — sender passes, key resolves in room state, but `untrusted_key`
///    fires before the decision can release the task.
/// 4. The positive path confirms the daemon's real signing key still releases it.
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_scheduler_rejects_decision_with_untrusted_key() {
    let _serial = enter_single_threaded_section();
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use mx_agent_protocol::signing::sign_approval_decision;

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");
    let sentinel = cwd.join("untrusted-key-approval-ran");
    let approver = "@approver:mx-agent.test";

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester = bob.user_id().expect("bob user id").to_string();

    let room = create_public_room(&bob, "mx-agent untrusted-key approval security test").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    // ── Throwaway key: room-published but NOT in the trust store ──
    //
    // A key in `verifying_keys` resolves check 3 (`unresolved_key`) but the
    // trust store gate (check 4, `untrusted_key`) still rejects it. This is the
    // issue #309 guarantee: room state alone is never the sole key anchor.
    let throwaway_raw = Ed25519SigningKey::from_bytes(&[33u8; 32]);
    let throwaway_key_id = key_id_for_verifying_key(&throwaway_raw.verifying_key());
    let throwaway_key_b64 = encode_verifying_key(&throwaway_raw.verifying_key());

    // Alice publishes the fake agent state so the throwaway key resolves in
    // `verifying_keys` (built from every `com.mxagent.agent.v1` state event).
    let alice_room_for_state = alice.get_room(&room_id).expect("alice has room");
    alice_room_for_state
        .send_state_event_raw(
            mx_agent_protocol::events::state::AGENT,
            "throwaway-agent-309",
            json!({
                "agent_id": "throwaway-agent-309",
                "kind": "pi",
                "matrix_user_id": alice_id.as_str(),
                "device_id": "THROWAWAY",
                "signing_key_id": &throwaway_key_id,
                "signing_public_key": &throwaway_key_b64,
                "status": "active",
                "capabilities": [],
                "tools": [],
                "load": { "running_invocations": 0, "max_invocations": 1 },
                "workspace": {
                    "cwd": cwd.to_string_lossy(),
                    "project_id": "test",
                    "git_commit": ""
                },
                "last_seen_ts": 0,
                "state_rev": 0
            }),
        )
        .await
        .expect("alice publishes throwaway agent state");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 2,
        },
    )
    .await
    .expect("register target agent");

    // Trust store: ONLY the daemon's real signing key — the throwaway key is not
    // added, so `is_key_trusted(throwaway_key_id)` returns false.
    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{approver}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
requires_approval = true
"#,
            room = room_id.as_str(),
            approver = approver,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    let task_id = "task-untrusted-key";
    let approval_id = format!("approval:{task_id}");
    create_task(
        &bob,
        &signed_exec_task(
            room_id.as_str(),
            task_id,
            &["sh", "-c", &format!("touch {}", sentinel.to_string_lossy())],
            &cwd,
            Vec::new(),
            &signing,
            approver,
        ),
    )
    .await
    .expect("create approval-required task");

    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };
    let scheduler = {
        let alice = alice.clone();
        let running = running.clone();
        std::thread::spawn(move || {
            run_scheduler_loop(
                alice,
                ExecSubscriberRegistry::new(),
                TaskDispatchMode::Local,
                running,
                Duration::from_secs(1),
            );
        })
    };

    let list_opts = ListTasksOptions {
        room: room_id.to_string(),
        state: None,
        assigned_to: None,
    };

    // Wait for scheduler to hold the task.
    let queue_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let pending = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
        if pending.iter().any(|p| p.request_id() == approval_id) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < queue_deadline,
            "scheduler should enqueue the pending approval within 60 s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ── Security negative test (issue #309): untrusted-key decision is dropped ──
    //
    // Alice (daemon's own Matrix user) sends a properly structured decision signed
    // with the throwaway key. The sender check passes (Alice = local_user), the key
    // resolves in verifying_keys (published in room state above), but check 4
    // (`untrusted_key`) fires because the trust store has no entry for it.
    let mut untrusted_decision = approval_decision_for(
        &approval_id,
        DECISION_APPROVED,
        alice_id.as_str(),
        "2026-06-13T10:00:00Z",
    );
    untrusted_decision.nonce = Some(format!("untrusted-key-nonce-{}", std::process::id()));
    untrusted_decision.expires_at = Some("2099-01-01T00:00:00Z".to_string());
    sign_approval_decision(&throwaway_raw, &throwaway_key_id, &mut untrusted_decision)
        .expect("sign with throwaway key");

    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice pre-emit sync");
    let alice_room = alice.get_room(&room_id).expect("alice has room after sync");
    emit_approval_decision(&alice_room, &untrusted_decision)
        .await
        .expect("alice emits untrusted-key decision");

    // Allow 10+ scheduler passes (1 s interval) for the untrusted decision to be
    // acted on if the fix were absent. The task must stay held.
    tokio::time::sleep(Duration::from_secs(10)).await;

    assert!(
        !sentinel.exists(),
        "decision signed by a room-published but untrusted key must not spawn the command \
         (issue #309 trust-store anchor)"
    );
    let held_state = list_tasks(&bob, &list_opts)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|t| t.task_id == task_id)
        .map(|t| t.state);
    assert_ne!(
        held_state.as_deref(),
        Some("succeeded"),
        "decision with an untrusted signing key must not release the task; state: {held_state:?}"
    );

    // ── Positive path: daemon's own signing key releases the task ──
    decide_approval_for_session(
        &alice_session,
        &paths,
        &approval_id,
        DECISION_APPROVED,
        alice_id.as_str(),
    )
    .await
    .expect("daemon approves the task");

    let approved_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut final_state = None;
    loop {
        if let Ok(tasks) = list_tasks(&bob, &list_opts).await {
            if let Some(t) = tasks.iter().find(|t| t.task_id == task_id) {
                final_state = Some(t.state.clone());
                if t.state == "succeeded" {
                    break;
                }
            }
        }
        if tokio::time::Instant::now() >= approved_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    running.store(false, Ordering::SeqCst);
    scheduler.join().expect("scheduler thread joins");
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");

    assert_eq!(
        final_state.as_deref(),
        Some("succeeded"),
        "task approved with a trusted signing key must run to succeeded; state: {final_state:?}"
    );
    assert!(
        sentinel.exists(),
        "legitimately approved task must spawn its command"
    );
}

/// Live cache-less expiry: a decision signed by the real daemon key but carrying
/// an `expires_at` timestamp in the past is rejected with `decision_expired` and
/// never releases the held task (issue #309).
///
/// The `decision_expired` check lives in `verification_failure`, which runs before
/// `ReplayCache::admit_at` is consulted, so a cache-less pass (companion issue
/// #305) cannot bypass it. This test confirms the guard holds end-to-end against a
/// real homeserver.
///
/// Steps:
/// 1. A `requires_approval` task is created; the scheduler holds it fail-closed.
/// 2. Alice emits a decision signed with the daemon's own key but stamped with an
///    `expires_at` value well in the past (`2020-01-01T00:00:00Z`).
/// 3. The scheduler rejects it (`decision_expired`) and the task stays held.
/// 4. A fresh, properly-stamped decision from the positive path releases the task.
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_scheduler_rejects_expired_decision() {
    let _serial = enter_single_threaded_section();
    use mx_agent_protocol::signing::sign_approval_decision;

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");
    let sentinel = cwd.join("expired-decision-approval-ran");
    let approver = "@approver:mx-agent.test";

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester = bob.user_id().expect("bob user id").to_string();

    let room = create_public_room(&bob, "mx-agent expired-decision approval security test").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 2,
        },
    )
    .await
    .expect("register target agent");

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{approver}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
requires_approval = true
"#,
            room = room_id.as_str(),
            approver = approver,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    let task_id = "task-expired-decision";
    let approval_id = format!("approval:{task_id}");
    create_task(
        &bob,
        &signed_exec_task(
            room_id.as_str(),
            task_id,
            &["sh", "-c", &format!("touch {}", sentinel.to_string_lossy())],
            &cwd,
            Vec::new(),
            &signing,
            approver,
        ),
    )
    .await
    .expect("create approval-required task");

    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };
    let scheduler = {
        let alice = alice.clone();
        let running = running.clone();
        std::thread::spawn(move || {
            run_scheduler_loop(
                alice,
                ExecSubscriberRegistry::new(),
                TaskDispatchMode::Local,
                running,
                Duration::from_secs(1),
            );
        })
    };

    let list_opts = ListTasksOptions {
        room: room_id.to_string(),
        state: None,
        assigned_to: None,
    };

    // Wait for scheduler to hold the task.
    let queue_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let pending = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
        if pending.iter().any(|p| p.request_id() == approval_id) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < queue_deadline,
            "scheduler should enqueue the pending approval within 60 s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ── Security negative test (issue #309): expired decision is dropped ──
    //
    // The decision is signed with the daemon's own signing key (passes sender +
    // key-resolution + trust-store checks), but its `expires_at` is `2020-01-01`
    // — well in the past. `verification_failure` check 7 fires (`decision_expired`)
    // before the replay cache is consulted, so this guard is cache-independent.
    let mut expired_decision = approval_decision_for(
        &approval_id,
        DECISION_APPROVED,
        alice_id.as_str(),
        "2026-06-13T10:00:00Z",
    );
    expired_decision.nonce = Some(format!("expired-nonce-{}", std::process::id()));
    // Deliberately past timestamp — must be rejected even though the key is trusted.
    expired_decision.expires_at = Some("2020-01-01T00:00:00Z".to_string());
    sign_approval_decision(
        signing.signing_key(),
        signing.key_id(),
        &mut expired_decision,
    )
    .expect("sign expired decision");

    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice pre-emit sync");
    let alice_room = alice.get_room(&room_id).expect("alice has room after sync");
    emit_approval_decision(&alice_room, &expired_decision)
        .await
        .expect("alice emits expired decision");

    // Allow 10+ passes; the task must stay held (decision_expired).
    tokio::time::sleep(Duration::from_secs(10)).await;

    assert!(
        !sentinel.exists(),
        "decision with a past expires_at must not spawn the command (issue #309 cache-less expiry)"
    );
    let held_state = list_tasks(&bob, &list_opts)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|t| t.task_id == task_id)
        .map(|t| t.state);
    assert_ne!(
        held_state.as_deref(),
        Some("succeeded"),
        "an expired decision must not release the task; state: {held_state:?}"
    );

    // ── Positive path: fresh decision with far-future expires_at releases the task ──
    decide_approval_for_session(
        &alice_session,
        &paths,
        &approval_id,
        DECISION_APPROVED,
        alice_id.as_str(),
    )
    .await
    .expect("daemon approves the task with a fresh decision");

    let approved_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut final_state = None;
    loop {
        if let Ok(tasks) = list_tasks(&bob, &list_opts).await {
            if let Some(t) = tasks.iter().find(|t| t.task_id == task_id) {
                final_state = Some(t.state.clone());
                if t.state == "succeeded" {
                    break;
                }
            }
        }
        if tokio::time::Instant::now() >= approved_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    running.store(false, Ordering::SeqCst);
    scheduler.join().expect("scheduler thread joins");
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");

    assert_eq!(
        final_state.as_deref(),
        Some("succeeded"),
        "task released by a fresh decision must run to succeeded; state: {final_state:?}"
    );
    assert!(
        sentinel.exists(),
        "legitimately approved task must spawn its command"
    );
}

/// Live approval-window expiry: a `requires_approval` task whose request window
/// lapses transitions to `blocked` with reason `approval_expired` without any
/// decision being issued (issue #309, follow-on from #265).
///
/// The approval queue (`approvals.json`) carries the request's `expires_at`. When
/// `approval_request_expired` returns `true` the scheduler blocks the task via
/// `block_approval_expired` and never spawns its command.
///
/// To force the expiry without waiting an hour, the test pre-populates the
/// approval queue with an entry whose `expires_at` is `2020-01-01T00:00:00Z`
/// before starting the scheduler. The first scheduler pass reads the expired
/// deadline and blocks the task.
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_approval_window_expiry_blocks_task() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");
    let sentinel = cwd.join("approval-window-expiry-ran");
    let approver = "@approver:mx-agent.test";

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester = bob.user_id().expect("bob user id").to_string();

    let room = create_public_room(&bob, "mx-agent approval-window expiry test").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 2,
        },
    )
    .await
    .expect("register target agent");

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{approver}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
requires_approval = true
"#,
            room = room_id.as_str(),
            approver = approver,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    let task_id = "task-window-expiry";
    let approval_id = format!("approval:{task_id}");
    create_task(
        &bob,
        &signed_exec_task(
            room_id.as_str(),
            task_id,
            &["sh", "-c", &format!("touch {}", sentinel.to_string_lossy())],
            &cwd,
            Vec::new(),
            &signing,
            approver,
        ),
    )
    .await
    .expect("create approval-required task");

    // ── Pre-populate the approval queue with an already-expired entry ──
    //
    // `QueueApprovalGate::evaluate` reads the deadline from the on-disk queue entry
    // first (falling back to the per-pass stamp only when no entry exists). By
    // writing an entry with `expires_at` in the past before the scheduler starts,
    // the first pass will find the expired deadline and immediately block the task
    // instead of waiting a full APPROVAL_REQUEST_TTL (one hour).
    let mut pre_queue = ApprovalQueue::default();
    pre_queue.enqueue(PendingApproval {
        room_id: room_id.to_string(),
        request: ApprovalRequest {
            request_id: approval_id.clone(),
            invocation_id: String::new(),
            requester: approver.to_string(),
            target: TARGET_AGENT.to_string(),
            summary: format!("Run exec action for task {task_id}"),
            risk: "medium".to_string(),
            expires_at: "2020-01-01T00:00:00Z".to_string(),
            extra: Default::default(),
        },
        // This is a task-backed hold (released by the scheduler), so it carries
        // no live-resume material (issue #306).
        held_request: None,
    });
    pre_queue
        .save(&paths)
        .expect("save pre-expired approval queue");

    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };
    let scheduler = {
        let alice = alice.clone();
        let running = running.clone();
        std::thread::spawn(move || {
            run_scheduler_loop(
                alice,
                ExecSubscriberRegistry::new(),
                TaskDispatchMode::Local,
                running,
                Duration::from_secs(1),
            );
        })
    };

    let list_opts = ListTasksOptions {
        room: room_id.to_string(),
        state: None,
        assigned_to: None,
    };

    // Wait for scheduler to detect the expired window and block the task.
    let expiry_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let final_task = loop {
        if let Ok(tasks) = list_tasks(&bob, &list_opts).await {
            if let Some(t) = tasks.iter().find(|t| t.task_id == task_id) {
                if t.state == "blocked" {
                    break t.clone();
                }
            }
        }
        assert!(
            tokio::time::Instant::now() < expiry_deadline,
            "scheduler should block the task as approval_expired within 60 s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    running.store(false, Ordering::SeqCst);
    scheduler.join().expect("scheduler thread joins");
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");

    assert!(
        !sentinel.exists(),
        "approval-expired task must never spawn its command"
    );
    let task = final_task;
    assert_eq!(
        task.state, "blocked",
        "task whose approval window expired must be blocked; state: {}",
        task.state
    );
    let reason = task
        .result
        .as_ref()
        .and_then(|r| r.get("reason"))
        .and_then(|v| v.as_str());
    assert_eq!(
        reason,
        Some("approval_expired"),
        "blocked task must carry reason 'approval_expired'; result: {:?}",
        task.result
    );
}

/// Live approver allowlist: a non-daemon Matrix user configured in the room's
/// `approvers` policy can release a held task when their signing key is trusted;
/// the daemon's own account also remains authorized (issue #309).
///
/// Steps:
/// 1. Bob's Matrix user id is added to the room policy `approvers` list.
/// 2. Bob generates a signing key and publishes it via a `com.mxagent.agent.v1`
///    state event; Alice's trust store is updated to trust Bob's key.
/// 3. Bob publishes a decision for the held task signed with his trusted key.
/// 4. The scheduler verifies sender (Bob in approvers), key resolves, key trusted,
///    signature valid, replay material present and unexpired — releases the task.
/// 5. The task runs to `succeeded` and the sentinel is created.
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_approver_allowlist_releases_task() {
    let _serial = enter_single_threaded_section();
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use mx_agent_protocol::signing::sign_approval_decision;

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");
    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);
    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");
    let sentinel = cwd.join("approver-allowlist-ran");
    let approver_agent = "@approver:mx-agent.test";

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester = bob.user_id().expect("bob user id").to_string();
    let bob_id = bob.user_id().expect("bob user id").to_owned();

    let room = create_public_room(&bob, "mx-agent approver-allowlist test").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&room, &alice_id).await;
    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob_id.as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice and bob");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    // ── Bob's signing identity: trusted key, published in room state ──
    //
    // Bob is a room member who is also a configured approver. His Ed25519 key is
    // distinct from Alice's daemon key — it must be trusted in Alice's trust store
    // and published via `com.mxagent.agent.v1` so it resolves in `verifying_keys`.
    let bob_signing_raw = Ed25519SigningKey::from_bytes(&[44u8; 32]);
    let bob_key_id = key_id_for_verifying_key(&bob_signing_raw.verifying_key());
    let bob_key_b64 = encode_verifying_key(&bob_signing_raw.verifying_key());

    // Bob publishes his agent state so his key is room-published.
    bob.sync_once(SyncSettings::default())
        .await
        .expect("bob sync before state event");
    let bob_room = bob.get_room(&room_id).expect("bob has room");
    bob_room
        .send_state_event_raw(
            mx_agent_protocol::events::state::AGENT,
            "bob-approver-agent",
            json!({
                "agent_id": "bob-approver-agent",
                "kind": "pi",
                "matrix_user_id": bob_id.as_str(),
                "device_id": "BOB-DEV",
                "signing_key_id": &bob_key_id,
                "signing_public_key": &bob_key_b64,
                "status": "active",
                "capabilities": [],
                "tools": [],
                "load": { "running_invocations": 0, "max_invocations": 1 },
                "workspace": {
                    "cwd": cwd.to_string_lossy(),
                    "project_id": "test",
                    "git_commit": ""
                },
                "last_seen_ts": 0,
                "state_rev": 0
            }),
        )
        .await
        .expect("bob publishes his agent state with his signing key");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 2,
        },
    )
    .await
    .expect("register target agent");

    // Trust store: daemon key (for task-action verification) AND Bob's key (so
    // `is_key_trusted(bob_key_id)` returns true and his decision is admitted).
    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.approve(
        "bob-approver-agent",
        &bob_key_id,
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");

    // Policy: `approvers` includes Bob's Matrix user id (union with daemon default).
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true
approvers = ["{bob}"]

[rooms."{room}".agents."{approver}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
requires_approval = true
"#,
            room = room_id.as_str(),
            bob = bob_id.as_str(),
            approver = approver_agent,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy with approver allowlist");

    let task_id = "task-approver-allowlist";
    let approval_id = format!("approval:{task_id}");
    create_task(
        &bob,
        &signed_exec_task(
            room_id.as_str(),
            task_id,
            &["sh", "-c", &format!("touch {}", sentinel.to_string_lossy())],
            &cwd,
            Vec::new(),
            &signing,
            approver_agent,
        ),
    )
    .await
    .expect("create approval-required task");

    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        tokio::spawn(async move {
            run_matrix_sync(&alice, &paths, health, BackoffConfig::default(), running).await
        })
    };
    let scheduler = {
        let alice = alice.clone();
        let running = running.clone();
        std::thread::spawn(move || {
            run_scheduler_loop(
                alice,
                ExecSubscriberRegistry::new(),
                TaskDispatchMode::Local,
                running,
                Duration::from_secs(1),
            );
        })
    };

    let list_opts = ListTasksOptions {
        room: room_id.to_string(),
        state: None,
        assigned_to: None,
    };

    // Wait for scheduler to hold the task (approval entry queued).
    let queue_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let pending = list_pending_approvals(&paths, Some(room_id.as_str())).unwrap_or_default();
        if pending.iter().any(|p| p.request_id() == approval_id) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < queue_deadline,
            "scheduler should enqueue the pending approval within 60 s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ── Positive test: Bob (configured approver) releases the task ──
    //
    // Bob sends a decision from his own Matrix user, signed with his trusted key.
    // The scheduler verifies: sender in {local_user} ∪ {bob_id} (passes), key
    // resolves (room-published), key trusted (trust store), signature valid, replay
    // material present and unexpired — releases the task.
    let mut bob_decision = approval_decision_for(
        &approval_id,
        DECISION_APPROVED,
        bob_id.as_str(),
        "2026-06-13T10:00:00Z",
    );
    bob_decision.nonce = Some(format!("allowlist-nonce-{}", std::process::id()));
    bob_decision.expires_at = Some("2099-01-01T00:00:00Z".to_string());
    sign_approval_decision(&bob_signing_raw, &bob_key_id, &mut bob_decision)
        .expect("bob signs the decision");

    bob.sync_once(SyncSettings::default())
        .await
        .expect("bob pre-emit sync");
    let bob_room_for_decision = bob.get_room(&room_id).expect("bob has room for decision");
    emit_approval_decision(&bob_room_for_decision, &bob_decision)
        .await
        .expect("bob emits approval decision");

    let approved_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut final_state = None;
    loop {
        if let Ok(tasks) = list_tasks(&bob, &list_opts).await {
            if let Some(t) = tasks.iter().find(|t| t.task_id == task_id) {
                final_state = Some(t.state.clone());
                if t.state == "succeeded" {
                    break;
                }
            }
        }
        if tokio::time::Instant::now() >= approved_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Dump task states for CI diagnostics.
    if let Ok(tasks) = list_tasks(&bob, &list_opts).await {
        for t in &tasks {
            eprintln!(
                "DIAG task={} state={} result={}",
                t.task_id,
                t.state,
                t.result
                    .as_ref()
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "null".to_string())
            );
        }
    }

    running.store(false, Ordering::SeqCst);
    scheduler.join().expect("scheduler thread joins");
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");

    assert_eq!(
        final_state.as_deref(),
        Some("succeeded"),
        "task approved by a configured allowlist approver must run to succeeded; \
         state: {final_state:?}"
    );
    assert!(
        sentinel.exists(),
        "task released by a configured non-daemon approver must spawn its command"
    );
}

/// E2EE media confidentiality round-trip (issue #308).
///
/// Proves two acceptance criteria for the `--e2ee on` workspace media path:
///
/// 1. **Artifact encryption.** An exec whose stdout exceeds the 256 KiB
///    `DEFAULT_MAX_TIMELINE_OUTPUT_BYTES` threshold uploads the artifact with
///    [`Client::upload_encrypted_file`]; the `com.mxagent.stream.artifact.v1`
///    event carries `EncryptedFile` key material, and the requester's
///    [`retrieve_artifact`] download + decrypt round-trips the original bytes.
///
/// 2. **Context-share encryption.** A context share whose payload exceeds the
///    256 KiB `MAX_INLINE_BYTES` inline threshold is uploaded with
///    [`Client::upload_encrypted_file`]; the `com.mxagent.context.share.v1`
///    event carries `EncryptedFile` key material, and [`fetch_context`] download
///    + decrypt round-trips the original bytes.
///
/// In both cases the homeserver holds only ciphertext blobs; the plaintext is
/// never readable by the homeserver operator even in an E2EE room.
///
/// **Security invariants preserved:** room encryption is a
/// transport/confidentiality property only — the Ed25519 signature +
/// trust-store + deny-by-default policy checks are still required for execution
/// permission. This test does not weaken the authorization model.
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_e2ee_media_round_trip_encrypts_artifacts_and_shares() {
    let _serial = enter_single_threaded_section();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let data_dir = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &data_dir);
    let paths = SessionPaths::resolve();
    paths.ensure_data_dir().expect("create data dir");

    let config_dir = data_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::env::set_var("MX_AGENT_CONFIG_DIR", &config_dir);

    let cwd = data_dir.join("work");
    std::fs::create_dir_all(&cwd).expect("create work dir");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");
    let requester_agent = bob.user_id().expect("bob user id").to_string();
    let bob_id = bob.user_id().expect("bob user id").to_owned();
    let alice_id = alice.user_id().expect("alice user id").to_owned();

    // Create an **encrypted** room — all timeline events and media uploads inside
    // must use E2EE (issue #308). Alice is the daemon; Bob is the requester.
    let room = create_encrypted_room(&bob, "mx-agent E2EE media round-trip").await;
    let room_id = room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins encrypted room");
    wait_for_joined_member(&room, &alice_id).await;

    room.send_state_event_raw(
        "m.room.power_levels",
        "",
        json!({
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
            "users": {
                bob.user_id().expect("bob user id").as_str(): 100,
                alice_id.as_str(): 50,
            },
            "events": { mx_agent_protocol::events::state::AGENT: 50 },
        }),
    )
    .await
    .expect("grant state-event power to alice");
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice observes power levels");

    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(requester_agent.clone()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 2,
        },
    )
    .await
    .expect("register requester agent");
    register_agent(
        &alice,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(TARGET_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            cwd: cwd.to_string_lossy().into_owned(),
            project_id: "mx-agent-it".to_string(),
            max_invocations: 2,
        },
    )
    .await
    .expect("register target agent");

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let mut trust = TrustStore::default();
    trust.approve(
        requester_agent.clone(),
        signing.key_id(),
        None,
        Some(room_id.to_string()),
        None,
    );
    trust.save(&paths).expect("save trust store");
    std::fs::write(
        config_dir.join("policy.toml"),
        format!(
            r#"
[rooms."{room}"]
trusted = true

[rooms."{room}".agents."{agent}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
"#,
            room = room_id.as_str(),
            agent = requester_agent,
            cwd = cwd.to_string_lossy(),
        ),
    )
    .expect("write policy");

    let subscribers = ExecSubscriberRegistry::new();
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let alice_sync = {
        let alice = alice.clone();
        let paths = paths.clone();
        let health = health.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &alice,
                &paths,
                health,
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };
    let bob_sync_paths = paths_in(data_dir.join("bob-sync"));
    bob_sync_paths
        .ensure_data_dir()
        .expect("create bob sync dir");
    let bob_sync = {
        let bob = bob.clone();
        let paths = bob_sync_paths.clone();
        let running = running.clone();
        let subscribers = subscribers.clone();
        tokio::spawn(async move {
            run_matrix_sync_with_subscribers(
                &bob,
                &paths,
                Arc::new(Mutex::new(SyncHealth::initializing(false))),
                BackoffConfig::default(),
                running,
                Some(subscribers),
            )
            .await
        })
    };
    save_session(&paths, &bob_session).expect("save requester session");

    // ── Test 1: Artifact encryption ───────────────────────────────────────────
    //
    // Run a command that produces exactly 270 000 bytes of stdout (well above the
    // 256 KiB = 262 144 byte threshold). In an E2EE room `emit_output_events`
    // must call `upload_encrypted_file`; the resulting `StreamArtifact` event
    // carries `EncryptedFile` key material and a ciphertext `mxc_uri`.
    let big_result = start_exec_matrix(
        &ExecStartParams {
            room: Some(room_id.to_string()),
            agent: Some(TARGET_AGENT.to_string()),
            // `dd` is available on every POSIX host; `tr` converts NULs to 'x'.
            // Both together produce exactly 270 000 'x' bytes on stdout.
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "dd if=/dev/zero bs=270000 count=1 2>/dev/null | tr '\\0' x".to_string(),
            ],
            cwd: Some(cwd.clone()),
            stdin: None,
            stream: true,
            pty: false,
            task: None,
            strict_stream: false,
            env: Default::default(),
            timeout_ms: Some(60_000),
            invocation_id: None,
        },
        &subscribers,
    )
    .await;

    let invocation_id = big_result.invocation_id.clone();
    let artifact_event = match &big_result.outcome {
        ExecOutcome::Ok { frames } => frames
            .iter()
            .find_map(|f| {
                if let ExecFrame::Artifact(a) = f {
                    Some(a.clone())
                } else {
                    None
                }
            })
            .expect(
                "exec producing 270 000 bytes (> 256 KiB threshold) must deliver \
                 an Artifact frame; check that the daemon is running and is in the room",
            ),
        ExecOutcome::Error { message, .. } => {
            panic!("exec failed unexpectedly (expected >256 KiB artifact upload): {message}")
        }
    };

    // The event must carry EncryptedFile key material — not a plain mxc_uri
    // reference — because the destination room has E2EE enabled (issue #308).
    assert!(
        artifact_event.encrypted_file.is_some(),
        "StreamArtifact in an E2EE room must carry EncryptedFile key material \
         so the homeserver cannot read the artifact bytes; got: {artifact_event:?}"
    );
    assert!(
        !artifact_event.mxc_uri.is_empty(),
        "StreamArtifact must carry a ciphertext mxc_uri referencing the encrypted blob"
    );

    // Round-trip: retrieve the artifact via Bob's client. `download_media` uses
    // `MediaSource::Encrypted` when `encrypted_file` is present, so the matrix
    // SDK downloads the ciphertext blob and decrypts it with the EncryptedFile
    // key material. `verify_and_decompress` then checks the plaintext SHA-256
    // before decompressing (if the artifact was compressed with zstd).
    let retrieved = retrieve_artifact(
        &bob,
        &RetrieveArtifactOptions {
            room: room_id.to_string(),
            invocation_id: invocation_id.clone(),
            stream: StreamKind::Stdout,
            limit: DEFAULT_ARTIFACT_SCAN_LIMIT,
            expected_sender: Some(alice_id.to_string()),
        },
    )
    .await
    .expect(
        "retrieve_artifact must decrypt and verify the encrypted media artifact \
         (issue #308: homeserver holds ciphertext; client decrypts with EncryptedFile key)",
    );

    assert_eq!(
        retrieved.data.len(),
        270_000,
        "artifact must round-trip to 270 000 bytes (the full command output)"
    );
    assert!(
        retrieved.data.iter().all(|&b| b == b'x'),
        "artifact content must consist entirely of 'x' bytes after decryption"
    );
    assert!(
        retrieved.artifact.encrypted_file.is_some(),
        "retrieved artifact must preserve the EncryptedFile key material in its event"
    );

    // ── Test 2: Context-share encryption ─────────────────────────────────────
    //
    // Bob shares 270 KiB of data into the encrypted room. Because the payload
    // exceeds MAX_INLINE_BYTES (256 KiB) it is uploaded as Matrix media; because
    // the room has E2EE enabled, `share_context` calls `upload_encrypted_file`
    // and records the EncryptedFile key material on the share event (issue #308).
    let share_data: Vec<u8> = (0u8..=255).cycle().take(270 * 1024).collect();
    let share = share_context(
        &bob,
        &ShareContextOptions {
            room: room_id.to_string(),
            name: "large-share.bin".to_string(),
            mime_type: "application/octet-stream".to_string(),
            data: share_data.clone(),
        },
    )
    .await
    .expect("share_context (>256 KiB) in an E2EE room should succeed");

    assert!(
        share.mxc_uri.is_some(),
        "large share must use media-backed transport (mxc_uri must be set)"
    );
    assert!(
        share.encrypted_file.is_some(),
        "large share in an E2EE room must carry EncryptedFile key material \
         so the homeserver cannot read the payload; got: {share:?}"
    );
    assert!(
        share.data.is_none(),
        "media-backed share must not inline the payload in the event"
    );

    // Round-trip: retrieve and decrypt the share via Alice's client. Alice's
    // sync loop has received Bob's encrypted share event (Megolm-decryptable
    // since both are room members); `fetch_context` locates it, downloads the
    // ciphertext blob, decrypts with the EncryptedFile key material, and
    // verifies the SHA-256 of the plaintext against the share's `sha256` field.
    let fetched = fetch_context(
        &alice,
        &FetchContextOptions {
            room: room_id.to_string(),
            context_id: share.context_id.clone(),
            limit: 100,
            expected_sender: Some(bob_id.to_string()),
        },
    )
    .await
    .expect(
        "fetch_context must decrypt and verify the encrypted share bytes \
         (issue #308: homeserver holds ciphertext; client decrypts with EncryptedFile key)",
    );

    assert_eq!(
        fetched.data, share_data,
        "fetch_context must return the exact original share bytes after decryption"
    );

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("alice sync joins")
        .expect("alice sync exits cleanly");
    bob_sync
        .await
        .expect("bob sync joins")
        .expect("bob sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");
}

/// Path to the compiled `mx-agent` CLI binary, located next to this
/// integration-test binary (`target/<profile>/deps/<test>` →
/// `target/<profile>/mx-agent`).
///
/// The `mx-agent` binary is defined in the `mx-agent-cli` crate, so the daemon
/// crate's tests cannot use `env!("CARGO_BIN_EXE_mx-agent")`. The integration
/// harness (`scripts/matrix_integration_test.sh`) builds it before running this
/// suite; a direct `cargo test` invocation must build it first.
fn mx_agent_bin() -> std::path::PathBuf {
    let mut dir = std::env::current_exe().expect("current test exe path");
    dir.pop(); // drop the test binary file name
    if dir.ends_with("deps") {
        dir.pop(); // drop the `deps` directory
    }
    dir.join("mx-agent")
}

/// Live no-secrets-in-logs end-to-end check through the **real daemon process**
/// (issue #311).
///
/// This is the process-level acceptance test for the operational-log redaction
/// goal. It drives the compiled `mx-agent` binary through a real
/// `auth login` → `daemon start` → `recovery enable` → `recovery recover` flow
/// against the live homeserver, then greps the captured `daemon.log` and every
/// CLI process's stderr for the actual access token and recovery key. Neither
/// secret may appear in either place.
///
/// **Why a process test rather than in-process calls.** `daemon.log` only
/// exists when the daemon runs as a background process: `start_background` opens
/// it `0600` and redirects the foreground daemon's stdout+stderr into it (see
/// [`crate::lifecycle`]). The credential-redaction behaviours themselves —
/// `session::Secret` `Debug`/`Display`, `RecoverParams` redaction, and the
/// telemetry subscriber's `Redacting` field formatter — are unit-tested in
/// `session.rs`, `recovery_ipc.rs`, `verification.rs`, and `mx_agent_telemetry`.
/// This test proves they actually hold for the *running daemon* and the *real
/// CLI*, with real homeserver-issued secrets, end to end — which the previous
/// in-process variant of this test did not (it only formatted `Debug` strings
/// and a scoped subscriber buffer, never reading `daemon.log` or capturing a
/// child process's stderr).
///
/// **Flow**
/// 1. `auth login` (password supplied via `MX_AGENT_PASSWORD`, never argv)
///    writes `session.json`; the real access token is read back from it.
/// 2. `daemon start` spawns the daemon, which loads the session and runs the
///    real sync loop; `daemon.log` is created `0600`.
/// 3. `recovery enable --json` provisions SSSS + key backup over IPC and returns
///    the one-time recovery key. That is the key's only legitimate appearance
///    (the enable command's *stdout*), so enable's stdout is deliberately
///    excluded from the grep set.
/// 4. `recovery recover` re-imports keys over IPC with the key fed via
///    `MX_AGENT_RECOVERY_KEY` (never argv), exercising `recover_for_session`'s
///    `RecoverParams` path inside the daemon.
///
/// `MX_AGENT_LOG=debug` maximises the leak surface: a stray
/// `tracing::debug!(token = …)` or `?params` anywhere on these paths would land
/// in `daemon.log` and fail the test.
///
/// **Isolation.** A dedicated fresh-per-run user with pristine cross-signing
/// state (`MX_AGENT_TEST_LOGREDACT_USER`, falling back to the recovery user and
/// then the shared user) so `recovery enable` bootstraps cleanly regardless of
/// test order, plus throwaway runtime/data dirs.
///
/// Run via `scripts/matrix_integration_test.sh`.
#[test]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
fn live_no_secrets_in_daemon_log_after_login_and_recover() {
    let _serial = enter_single_threaded_section();
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use std::time::{Duration, Instant};

    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    // Prefer a dedicated fresh-per-run user (pristine cross-signing) so
    // `recovery enable` bootstraps cleanly no matter which recovery test runs
    // first; fall back to the recovery user, then the shared user, so a direct
    // `cargo test` invocation against a freshly-reset homeserver still runs.
    let user = std::env::var("MX_AGENT_TEST_LOGREDACT_USER")
        .or_else(|_| std::env::var("MX_AGENT_TEST_RECOVERY_USER"))
        .unwrap_or_else(|_| required_env("MX_AGENT_TEST_USER"));
    let pass = std::env::var("MX_AGENT_TEST_LOGREDACT_PASSWORD")
        .or_else(|_| std::env::var("MX_AGENT_TEST_RECOVERY_PASSWORD"))
        .unwrap_or_else(|_| required_env("MX_AGENT_TEST_PASSWORD"));

    let bin = mx_agent_bin();
    assert!(
        bin.exists(),
        "mx-agent binary not found at {} — build it first \
         (`cargo build -p mx-agent-cli`); the matrix integration harness does this",
        bin.display()
    );

    // Throwaway, per-run dirs. The runtime dir (which holds daemon.log and the
    // IPC socket) lives under the data dir so a single `remove_dir_all` cleans
    // both up. Both must be `0700`: the daemon refuses to bind its socket in a
    // group/other-accessible runtime dir (`ensure_safe_parent_dir`,
    // `UNSAFE_DIR_BITS == 0o077`), so create them privately up front regardless
    // of the ambient umask.
    let data_dir = throwaway_data_dir();
    let runtime_dir = data_dir.join("runtime");
    for dir in [&data_dir, &runtime_dir] {
        std::fs::create_dir_all(dir).expect("create test dir");
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .expect("tighten test dir to 0700");
    }

    // Run `mx-agent <args>` with isolated dirs and verbose (debug) logging.
    // Secrets are never inherited from the ambient environment; the only secret
    // env vars are the ones explicitly passed via `extra_env` per call.
    let mx = |args: &[&str], extra_env: &[(&str, &str)]| -> std::process::Output {
        let mut cmd = Command::new(&bin);
        cmd.args(args)
            .env("MX_AGENT_DATA_DIR", &data_dir)
            .env("MX_AGENT_RUNTIME_DIR", &runtime_dir)
            .env("MX_AGENT_LOG", "debug")
            .env_remove("MX_AGENT_PASSWORD")
            .env_remove("MX_AGENT_RECOVERY_KEY");
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.output().expect("failed to run mx-agent")
    };

    // Everything a secret must NOT appear in: daemon.log plus every CLI
    // process's stderr (and the non-secret stdouts). The recovery key's one
    // legitimate sink — `recovery enable`'s stdout — is excluded by design.
    let mut captured = String::new();

    // ── 1. Login (password via env, never argv) — CLI-local, writes session.json
    let login = mx(
        &[
            "auth",
            "login",
            "--homeserver",
            &homeserver,
            "--user",
            &user,
        ],
        &[("MX_AGENT_PASSWORD", &pass)],
    );
    captured.push_str(&String::from_utf8_lossy(&login.stderr));
    assert!(
        login.status.success(),
        "auth login must succeed: stderr={}",
        String::from_utf8_lossy(&login.stderr)
    );

    // Read the real access token back from the persisted session.
    let session_path = data_dir.join("session.json");
    let session_json = std::fs::read_to_string(&session_path).expect("read session.json");
    let session_val: Value = serde_json::from_str(&session_json).expect("parse session.json");
    let access_token = session_val
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("session.json must contain an access_token field")
        .to_string();
    assert!(
        !access_token.is_empty(),
        "homeserver must issue a non-empty access token"
    );

    // ── 2. Start the daemon in the background; daemon.log is created here.
    let start = mx(&["daemon", "start"], &[]);
    captured.push_str(&String::from_utf8_lossy(&start.stderr));
    assert!(
        start.status.success(),
        "daemon start must succeed: stderr={}",
        String::from_utf8_lossy(&start.stderr)
    );

    // Poll until the daemon reports running.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = mx(&["daemon", "status", "--json"], &[]);
        captured.push_str(&String::from_utf8_lossy(&status.stderr));
        if status.status.success() {
            captured.push_str(&String::from_utf8_lossy(&status.stdout));
            break;
        }
        assert!(Instant::now() < deadline, "daemon never became ready");
        std::thread::sleep(Duration::from_millis(100));
    }

    // ── 3. Enable recovery over IPC. The one-time key is returned on stdout —
    //    its only legitimate appearance — so enable's stdout is NOT captured.
    let enable = mx(&["recovery", "enable", "--json"], &[]);
    captured.push_str(&String::from_utf8_lossy(&enable.stderr));
    assert!(
        enable.status.success(),
        "recovery enable must succeed: stderr={}",
        String::from_utf8_lossy(&enable.stderr)
    );
    let enable_stdout = String::from_utf8_lossy(&enable.stdout);
    // Parse without echoing the raw stdout on failure (it carries the key).
    let enabled: RecoveryEnableResult = serde_json::from_str(enable_stdout.trim())
        .unwrap_or_else(|e| panic!("recovery enable --json must emit RecoveryEnableResult ({e})"));
    let recovery_key = enabled.recovery_key.expose().to_string();
    assert!(
        !recovery_key.is_empty(),
        "recovery enable must return a non-empty recovery key"
    );

    // ── 4. Recover over IPC with the key supplied via env (never argv). This
    //    drives the daemon's `recover_for_session` / `RecoverParams` path.
    let recover = mx(
        &["recovery", "recover"],
        &[("MX_AGENT_RECOVERY_KEY", &recovery_key)],
    );
    captured.push_str(&String::from_utf8_lossy(&recover.stderr));
    captured.push_str(&String::from_utf8_lossy(&recover.stdout));
    assert!(
        recover.status.success(),
        "recovery recover must succeed: stderr={}",
        String::from_utf8_lossy(&recover.stderr)
    );

    // Stop the daemon before inspecting its log.
    let stop = mx(&["daemon", "stop"], &[]);
    captured.push_str(&String::from_utf8_lossy(&stop.stderr));

    // ── Read the captured daemon.log (the daemon's own stdout+stderr).
    let log_path = runtime_dir.join("daemon.log");
    let daemon_log = std::fs::read_to_string(&log_path).expect("read daemon.log");

    // daemon.log must be owner-only (0600) regardless of umask (issue #311).
    let mode = std::fs::metadata(&log_path)
        .expect("stat daemon.log")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "daemon.log must be private (0600)");

    // The daemon must actually have logged at debug, so the absences below are
    // meaningful rather than an empty-file artifact.
    assert!(
        !daemon_log.trim().is_empty(),
        "daemon.log is empty; MX_AGENT_LOG=debug should have produced operational logs"
    );

    // ── The acceptance assertions: neither secret appears in daemon.log or in
    //    any CLI process's stderr/stdout. Failure messages deliberately omit the
    //    secret values so a failure never re-leaks them into CI output.
    assert!(
        !daemon_log.contains(&access_token),
        "access token leaked into daemon.log (issue #311)"
    );
    assert!(
        !daemon_log.contains(&recovery_key),
        "recovery key leaked into daemon.log (issue #311)"
    );
    assert!(
        !captured.contains(&access_token),
        "access token leaked into a CLI process's stderr/stdout (issue #311)"
    );
    assert!(
        !captured.contains(&recovery_key),
        "recovery key leaked into a CLI process's stderr/stdout (issue #311)"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

/// Sender-pin enforcement for `read_latest_heartbeats` (issue #312 §1).
///
/// Proves that a spoofed `com.mxagent.heartbeat.v1` timeline event — sent by
/// Alice claiming BOB_AGENT's `agent_id` — is silently rejected by the
/// sender-pin check in [`read_latest_heartbeats`]. The check requires the event
/// `sender` to equal the registered agent's `matrix_user_id`; Alice's sender
/// differs from Bob's registered `matrix_user_id`, so the spoof is skipped and
/// the genuine earlier heartbeat Bob emitted is returned instead.
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_spoofed_heartbeat_is_ignored_by_sender_pin() {
    let _serial = enter_single_threaded_section();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let alice_user = required_env("MX_AGENT_TEST_USER");
    let alice_pass = required_env("MX_AGENT_TEST_PASSWORD");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let alice_session = login_password(&config, &alice_user, &alice_pass)
        .await
        .expect("alice login");
    let alice = restore_client(&alice_session).await.expect("alice restore");
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");

    // Bob creates the room; Alice joins. Default PublicChat power levels give
    // Bob PL 100 (state events allowed) and Alice PL 0 (timeline only).
    let bob_room = create_public_room(&bob, "mx-agent heartbeat sender-pin e2e").await;
    let room_id = bob_room.room_id().to_owned();
    alice
        .join_room_by_id(&room_id)
        .await
        .expect("alice joins room");
    let alice_id = alice.user_id().expect("alice user id").to_owned();
    wait_for_joined_member(&bob_room, &alice_id).await;

    // Alice syncs to establish a pagination token (required for room.messages).
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice initial sync");

    // Bob registers BOB_AGENT. PL 100 > state_default 50 → allowed.
    let base = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &base);
    paths_in(base.clone())
        .ensure_data_dir()
        .expect("create data dir");
    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(BOB_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec![],
            tools: vec![],
            cwd: "/tmp".to_string(),
            project_id: "sender-pin-test".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register BOB_AGENT");
    std::env::remove_var(ENV_DATA_DIR);

    // Alice syncs to see Bob's registered agent state; `emit_heartbeat` via
    // alice_room reads the state to check status_changed — it must see Bob's
    // status ("active") before Alice's spoof call.
    alice
        .sync_once(SyncSettings::default())
        .await
        .expect("alice syncs agent registration");
    let alice_room = alice.get_room(&room_id).expect("alice is in room");

    // Get the registered agent state (needed for the sender-pin map).
    let bob_state = list_agents(
        &alice,
        &ListAgentsOptions {
            room: room_id.to_string(),
            capabilities: vec![],
        },
    )
    .await
    .expect("list agents via alice")
    .into_iter()
    .find(|a| a.agent_id == BOB_AGENT)
    .expect("BOB_AGENT must be visible to alice after her sync");
    assert_eq!(
        bob_state.matrix_user_id,
        bob.user_id().expect("bob user id").as_str(),
        "BOB_AGENT's matrix_user_id must be Bob's"
    );

    // Bob emits a genuine heartbeat. Use a very long state_refresh to skip the
    // durable-state rewrite (the timeline event is what we are testing).
    let hb_cfg = HeartbeatConfig {
        state_refresh: Duration::from_secs(999_999),
        ..HeartbeatConfig::default()
    };
    emit_heartbeat(&bob_room, BOB_AGENT, "active", &hb_cfg, 0)
        .await
        .expect("bob emits genuine heartbeat");

    // Record a timestamp AFTER Bob's genuine heartbeat but BEFORE Alice's spoof,
    // so we can distinguish which heartbeat the scan returns: Bob's ts <
    // before_spoof_ms < Alice's ts.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let before_spoof_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default();
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Alice emits a spoofed heartbeat for BOB_AGENT.
    // Conditions to prevent Alice from triggering a durable-state rewrite she
    // lacks power to write (Alice is PL 0; state_default is 50):
    // - status = "active" matches the registered status → status_changed=false.
    // - last_state_ms = u64::MAX → now_ms.saturating_sub(u64::MAX)=0 <
    //   state_refresh ms → time-based refresh disabled.
    emit_heartbeat(&alice_room, BOB_AGENT, "active", &hb_cfg, u64::MAX)
        .await
        .expect("alice emits spoofed heartbeat timeline event");

    // Scan backward. Alice's spoof is more recent (sender = alice, registered
    // sender = bob) → sender-pin rejects it. Bob's genuine heartbeat is older
    // (sender = bob == registered sender) → accepted.
    let latest = read_latest_heartbeats(&alice_room, &[bob_state], MAX_HEARTBEAT_SCAN_EVENTS)
        .await
        .expect("read_latest_heartbeats must succeed on live homeserver");

    assert!(
        latest.contains_key(BOB_AGENT),
        "scan must find a heartbeat for {BOB_AGENT}; found: {:?}",
        latest.keys().collect::<Vec<_>>()
    );
    // Bob's genuine heartbeat was stamped BEFORE before_spoof_ms; Alice's spoof
    // AFTER. A ts < before_spoof_ms proves the genuine heartbeat was returned.
    let hb = &latest[BOB_AGENT];
    assert!(
        hb.ts < before_spoof_ms,
        "returned heartbeat ts ({}) must predate the spoof threshold ({}): \
         a ts >= threshold means Alice's spoofed sender was incorrectly accepted",
        hb.ts,
        before_spoof_ms
    );
    assert_eq!(
        hb.agent_id, BOB_AGENT,
        "returned heartbeat must identify BOB_AGENT"
    );
}

/// Pagination coverage for `read_latest_heartbeats` on busy timelines (issue #312 §4).
///
/// Emits one genuine heartbeat for BOB_AGENT, then pushes it beyond the
/// first-page window by sending `HEARTBEAT_SCAN_LIMIT + 1` noise events.
/// Asserts:
///
/// - A single-page scan (`max_events = HEARTBEAT_SCAN_LIMIT = 100`) does NOT
///   find the heartbeat: it is buried at position 102 in the backward scan.
///   This reproduces the pre-fix regression where exec-stream chunks could
///   evict heartbeats from the one-page window.
/// - A paginating scan (`max_events = MAX_HEARTBEAT_SCAN_EVENTS = 1000`) finds
///   the heartbeat on the second page, proving that the bounded-pagination fix
///   recovers buried heartbeats.
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_heartbeat_pagination_finds_event_buried_under_noise() {
    let _serial = enter_single_threaded_section();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");

    let room = create_public_room(&bob, "mx-agent heartbeat pagination e2e").await;
    let room_id = room.room_id().to_owned();

    // Register BOB_AGENT. Bob (PL 100) can write agent state events.
    let base = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &base);
    paths_in(base.clone())
        .ensure_data_dir()
        .expect("create data dir");
    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(BOB_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec![],
            tools: vec![],
            cwd: "/tmp".to_string(),
            project_id: "pagination-test".to_string(),
            max_invocations: 1,
        },
    )
    .await
    .expect("register BOB_AGENT");
    std::env::remove_var(ENV_DATA_DIR);

    // Sync to populate the room's pagination token for room.messages().
    bob.sync_once(SyncSettings::default())
        .await
        .expect("bob initial sync");

    // Discover the registered agent state for the sender-pin map.
    let bob_state = list_agents(
        &bob,
        &ListAgentsOptions {
            room: room_id.to_string(),
            capabilities: vec![],
        },
    )
    .await
    .expect("list agents")
    .into_iter()
    .find(|a| a.agent_id == BOB_AGENT)
    .expect("BOB_AGENT registered");

    // Emit the heartbeat that will be buried under noise.
    let hb_cfg = HeartbeatConfig {
        state_refresh: Duration::from_secs(999_999),
        ..HeartbeatConfig::default()
    };
    emit_heartbeat(&room, BOB_AGENT, "active", &hb_cfg, 0)
        .await
        .expect("emit genuine heartbeat");

    // Push the heartbeat off the first scan page by emitting HEARTBEAT_SCAN_LIMIT + 1
    // noise events. The backward scan sees newest-first, so the noise events
    // occupy positions 1..=noise_count in the scan order, placing the heartbeat
    // at position noise_count + 1 = HEARTBEAT_SCAN_LIMIT + 2.
    // With per-page limit = HEARTBEAT_SCAN_LIMIT, the first page covers
    // positions 1..=HEARTBEAT_SCAN_LIMIT and the heartbeat is beyond it.
    let noise_count = HEARTBEAT_SCAN_LIMIT + 1;
    for i in 0..noise_count {
        room.send_raw(
            "m.room.message",
            json!({ "msgtype": "m.text", "body": format!("noise-{i}") }),
        )
        .await
        .unwrap_or_else(|e| panic!("send noise event {i}: {e}"));
    }

    // ---- Negative test: single-page scan must NOT find the buried heartbeat. ----
    let single_page = read_latest_heartbeats(
        &room,
        std::slice::from_ref(&bob_state),
        HEARTBEAT_SCAN_LIMIT,
    )
    .await
    .expect("single-page scan must succeed");
    assert!(
        !single_page.contains_key(BOB_AGENT),
        "single-page scan (max_events={HEARTBEAT_SCAN_LIMIT}) must NOT find \
         a heartbeat buried under {noise_count} noise events; \
         this reproduces the pre-fix regression"
    );

    // ---- Positive test: paginating scan must find it on the second page. ----
    let paginated = read_latest_heartbeats(&room, &[bob_state], MAX_HEARTBEAT_SCAN_EVENTS)
        .await
        .expect("paginating scan must succeed");
    assert!(
        paginated.contains_key(BOB_AGENT),
        "paginating scan (max_events={MAX_HEARTBEAT_SCAN_EVENTS}) must find \
         the heartbeat buried under {noise_count} noise events; \
         found: {:?}",
        paginated.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        paginated[BOB_AGENT].agent_id, BOB_AGENT,
        "found heartbeat must identify BOB_AGENT"
    );
}

/// In-flight invocation counter in heartbeats and heartbeat-enriched task
/// diagnostics (issue #312 §2 and §3).
///
/// Exercises two of the four gaps fixed in issue #312 end-to-end against a
/// live homeserver:
///
/// **running_invocations counter**: holding an
/// [`mx_agent_daemon::inflight::InflightGuard`] for BOB_AGENT increments the
/// process-global counter; the next [`emit_heartbeat`] call reads it and
/// publishes it in the `com.mxagent.heartbeat.v1` timeline event.
/// [`read_latest_heartbeats`] returns the emitted event with
/// `load.running_invocations = 1`. After the guard drops, a subsequent
/// heartbeat carries `running_invocations = 0`.
///
/// **task.graph liveness path**: [`list_agents_with_liveness_for_session`]
/// scans the heartbeat timeline and enriches the liveness verdict; the
/// resulting map passed to [`diagnose_tasks`] suppresses the false
/// `assigned_to_inactive_agent` warning a stale durable `last_seen_ts` would
/// otherwise trigger — reproducing the task.graph fix inline (issue #312 §3).
///
/// Run via `scripts/matrix_integration_test.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_running_invocations_and_task_diagnostics_use_heartbeat_liveness() {
    let _serial = enter_single_threaded_section();
    let homeserver = required_env("MX_AGENT_TEST_HOMESERVER");
    let bob_user = required_env("MX_AGENT_TEST_USER2");
    let bob_pass = required_env("MX_AGENT_TEST_PASSWORD2");

    let config = MatrixConfig {
        homeserver_url: homeserver,
    };
    let bob_session = login_password(&config, &bob_user, &bob_pass)
        .await
        .expect("bob login");
    let bob = restore_client(&bob_session).await.expect("bob restore");

    let room = create_public_room(&bob, "mx-agent inflight + task-liveness e2e").await;
    let room_id = room.room_id().to_owned();

    let base = throwaway_data_dir();
    std::env::set_var(ENV_DATA_DIR, &base);
    paths_in(base.clone())
        .ensure_data_dir()
        .expect("create data dir");
    register_agent(
        &bob,
        &RegisterAgentOptions {
            room: room_id.to_string(),
            agent_id: Some(BOB_AGENT.to_string()),
            kind: "pi".to_string(),
            capabilities: vec![],
            tools: vec![],
            cwd: "/tmp".to_string(),
            project_id: "inflight-test".to_string(),
            max_invocations: 4,
        },
    )
    .await
    .expect("register BOB_AGENT");
    std::env::remove_var(ENV_DATA_DIR);

    bob.sync_once(SyncSettings::default())
        .await
        .expect("bob initial sync");

    let bob_state = list_agents(
        &bob,
        &ListAgentsOptions {
            room: room_id.to_string(),
            capabilities: vec![],
        },
    )
    .await
    .expect("list agents")
    .into_iter()
    .find(|a| a.agent_id == BOB_AGENT)
    .expect("BOB_AGENT registered");

    // Force every emit_heartbeat call to also refresh the durable state, so the
    // durable `load.running_invocations` stays in sync with the timeline events.
    let hb_cfg = HeartbeatConfig {
        state_refresh: Duration::ZERO,
        ..HeartbeatConfig::default()
    };

    // ---- Criterion: running_invocations is published in heartbeat content. ----

    // Baseline: no guard held → heartbeat must carry running_invocations=0.
    emit_heartbeat(&room, BOB_AGENT, "active", &hb_cfg, 0)
        .await
        .expect("emit baseline heartbeat");
    let baseline = read_latest_heartbeats(
        &room,
        std::slice::from_ref(&bob_state),
        MAX_HEARTBEAT_SCAN_EVENTS,
    )
    .await
    .expect("read baseline heartbeat");
    assert_eq!(
        baseline
            .get(BOB_AGENT)
            .expect("baseline heartbeat for BOB_AGENT")
            .load
            .running_invocations,
        0,
        "baseline heartbeat must carry running_invocations=0 when no guard is held"
    );

    // Hold one InflightGuard and emit a heartbeat. The guard increments the
    // process-global counter; emit_heartbeat reads it via
    // inflight::running_invocations and embeds it in the event.
    let guard = mx_agent_daemon::inflight::InflightGuard::enter(BOB_AGENT);
    emit_heartbeat(&room, BOB_AGENT, "active", &hb_cfg, 0)
        .await
        .expect("emit heartbeat while inflight guard held");
    let inflight_hbs = read_latest_heartbeats(
        &room,
        std::slice::from_ref(&bob_state),
        MAX_HEARTBEAT_SCAN_EVENTS,
    )
    .await
    .expect("read heartbeat while inflight");
    assert_eq!(
        inflight_hbs
            .get(BOB_AGENT)
            .expect("in-flight heartbeat for BOB_AGENT")
            .load
            .running_invocations,
        1,
        "heartbeat while one InflightGuard is held must carry running_invocations=1"
    );

    // Drop the guard and emit another heartbeat: counter returns to 0.
    drop(guard);
    emit_heartbeat(&room, BOB_AGENT, "active", &hb_cfg, 0)
        .await
        .expect("emit heartbeat after guard dropped");
    let after_hbs = read_latest_heartbeats(
        &room,
        std::slice::from_ref(&bob_state),
        MAX_HEARTBEAT_SCAN_EVENTS,
    )
    .await
    .expect("read heartbeat after guard dropped");
    assert_eq!(
        after_hbs
            .get(BOB_AGENT)
            .expect("post-drop heartbeat for BOB_AGENT")
            .load
            .running_invocations,
        0,
        "heartbeat after guard drop must carry running_invocations=0"
    );

    // ---- Criterion: task.graph diagnostics use heartbeat-enriched liveness. ----
    // Create a planning task assigned to BOB_AGENT (no signed action needed).
    create_task(
        &bob,
        &CreateTaskOptions {
            room: room_id.to_string(),
            task_id: Some("test-312-hb-liveness".to_string()),
            title: "Heartbeat liveness e2e (issue #312)".to_string(),
            description: String::new(),
            state: None,
            assigned_to: BOB_AGENT.to_string(),
            created_by: None,
            depends_on: vec![],
            blocks: vec![],
            action: None,
        },
    )
    .await
    .expect("create test task");

    let tasks = list_tasks(
        &bob,
        &ListTasksOptions {
            room: room_id.to_string(),
            state: None,
            assigned_to: None,
        },
    )
    .await
    .expect("list tasks");
    assert!(!tasks.is_empty(), "at least one task must be in the room");

    // Replicate the task.graph IPC handler path (lifecycle.rs §task.graph):
    // call list_agents_with_liveness_for_session → build liveness map →
    // diagnose_tasks. This is the same code path the IPC handler executes.
    let listings = list_agents_with_liveness_for_session(
        &bob_session,
        &ListAgentsOptions {
            room: room_id.to_string(),
            capabilities: vec![],
        },
    )
    .await
    .expect("list_agents_with_liveness_for_session must succeed");

    let mut liveness_map: HashMap<String, Liveness> = HashMap::with_capacity(listings.len());
    let agents: Vec<_> = listings
        .into_iter()
        .map(|l| {
            liveness_map.insert(l.agent.agent_id.clone(), l.liveness);
            l.agent
        })
        .collect();

    // The heartbeat just emitted must have lifted the verdict to Active.
    assert_eq!(
        liveness_map.get(BOB_AGENT).copied(),
        Some(Liveness::Active),
        "list_agents_with_liveness_for_session must return Active for BOB_AGENT \
         after a fresh heartbeat"
    );

    // Synthesize a stale durable state (last_seen_ts=0) to model the gap between
    // the 300s durable-state refreshes. This is what triggers the false
    // `assigned_to_inactive_agent` warning the heartbeat fix suppresses.
    let mut stale = agents
        .iter()
        .find(|a| a.agent_id == BOB_AGENT)
        .expect("BOB_AGENT in agents")
        .clone();
    stale.last_seen_ts = 0;
    let stale_agents = [stale];

    // Without enrichment: durable-only liveness sees last_seen_ts=0 → Offline
    // → assigned_to_inactive_agent warning fires.
    let diags_durable_only: Vec<TaskDiagnostic> =
        diagnose_tasks(&tasks, &stale_agents, &HashMap::new());
    assert!(
        diags_durable_only
            .iter()
            .any(|d| d.kind == "assigned_to_inactive_agent"),
        "stale durable state (last_seen_ts=0) with no heartbeat enrichment must warn \
         assigned_to_inactive_agent; got: {diags_durable_only:?}"
    );

    // With heartbeat-enriched liveness map (Active): the warning is suppressed.
    let diags_enriched: Vec<TaskDiagnostic> = diagnose_tasks(&tasks, &stale_agents, &liveness_map);
    assert!(
        !diags_enriched
            .iter()
            .any(|d| d.kind == "assigned_to_inactive_agent"),
        "heartbeat-enriched Active verdict must suppress assigned_to_inactive_agent; \
         got: {diags_enriched:?}"
    );
}
