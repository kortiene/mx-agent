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

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use matrix_sdk::config::SyncSettings;
use matrix_sdk::ruma::api::client::room::{create_room, Visibility};
use matrix_sdk::ruma::events::room::member::MembershipState;
use matrix_sdk::ruma::events::room::message::{
    OriginalSyncRoomMessageEvent, RoomMessageEventContent,
};
use matrix_sdk::ruma::{EventId, UserId};
use matrix_sdk::{Client, Room};
use serde_json::{json, Value};

use mx_agent_daemon::session::ENV_DATA_DIR;
use mx_agent_daemon::{
    authorize_call_request, authorize_exec_request, build_signed_call_request,
    build_signed_exec_request, load_or_create_signing_key, load_sync_token, login_password,
    restore_client, run_matrix_sync, BackoffConfig, ExecRequestOptions, MatrixConfig, SessionPaths,
    SyncHealth, SyncState, TrustStore,
};
use mx_agent_policy::Policy;
use mx_agent_protocol::events::timeline;

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

    let mut create = create_room::v3::Request::new();
    create.name = Some("mx-agent integration test".to_owned());
    create.visibility = Visibility::Public;
    create.preset = Some(create_room::v3::RoomPreset::PublicChat);
    let room = bob.create_room(create).await.expect("bob creates room");
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
    SessionPaths {
        session_file: dir.join("session.json"),
        sync_token_file: dir.join("sync_token"),
        data_dir: dir,
    }
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

/// Create a public, end-to-end encrypted room owned by `client`.
///
/// `enable_encryption` sends the `m.room.encryption` state event and waits for
/// a sync to reflect it, so the caller must already be running a sync loop.
async fn create_encrypted_room(client: &Client, name: &str) -> Room {
    let mut create = create_room::v3::Request::new();
    create.name = Some(name.to_owned());
    // Public + PublicChat so the daemon user can `join_room_by_id`, and so the
    // (default `shared`) history visibility lets a late joiner fetch — but not
    // decrypt — events sent before it joined.
    create.visibility = Visibility::Public;
    create.preset = Some(create_room::v3::RoomPreset::PublicChat);
    let room = client
        .create_room(create)
        .await
        .expect("create encrypted room");
    room.enable_encryption()
        .await
        .expect("enable end-to-end encryption");
    assert!(
        room.encryption_state().is_encrypted(),
        "room should report encryption enabled"
    );
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
