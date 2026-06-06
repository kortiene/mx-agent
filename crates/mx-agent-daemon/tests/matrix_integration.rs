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
//! policy-denied action, and holding an approval-required action (fail closed)
//! — so none of those spawn a process they should not.
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
    build_signed_exec_request, create_task, list_tasks, load_or_create_signing_key,
    load_sync_token, login_password, register_agent, restore_client, run_matrix_sync,
    run_matrix_sync_with_subscribers, run_scheduler_loop, save_session, sign_task_action,
    start_call_matrix, start_exec_matrix, BackoffConfig, CallOutcome, CallStartParams,
    CreateTaskOptions, DaemonSigningKey, ExecFrame, ExecOutcome, ExecRequestOptions,
    ExecStartParams, ExecSubscriberRegistry, ListTasksOptions, MatrixConfig, RegisterAgentOptions,
    SessionPaths, SyncHealth, SyncState, TaskDispatchMode, TrustStore,
};
use mx_agent_policy::Policy;
use mx_agent_protocol::events::timeline;
use mx_agent_protocol::schema::TaskAction;

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

/// Live Matrix-backed remote call coverage (issue #194).
///
/// Drives two real Matrix users in one room: Bob registers a requester agent,
/// Alice registers the target agent and runs the daemon sync loop, Bob sends a
/// signed targeted call through `start_call_matrix`, and Alice's sync handler
/// verifies signature/trust/policy before executing the tool and emitting a
/// response.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_matrix_backed_remote_call_round_trips() {
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
    })
    .await;

    running.store(false, Ordering::SeqCst);
    alice_sync
        .await
        .expect("sync task joins")
        .expect("sync exits cleanly");
    std::env::remove_var(ENV_DATA_DIR);
    std::env::remove_var("MX_AGENT_CONFIG_DIR");

    match result.outcome {
        CallOutcome::Ok { exit_code, summary } => {
            assert_eq!(exit_code, 0, "remote tool summary: {summary}");
        }
        other => panic!("expected successful remote call, got {other:?}"),
    }
}

/// Live Matrix-backed remote exec coverage (issue #196).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local Matrix homeserver; run via scripts/matrix_integration_test.sh"]
async fn live_matrix_backed_remote_exec_round_trips_and_denies() {
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
        // Policy-allowed but `requires_approval`: with no approval gate wired,
        // the live scheduler must fail closed and never run it.
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
    // Approval safety: an action that requires approval is never executed by the
    // gate-less live scheduler (fail closed), so its command never spawns.
    assert_ne!(
        final_states.get("task-approval").map(String::as_str),
        Some("succeeded"),
        "approval-required task must not be executed without approval; states: {final_states:?}"
    );
    assert!(
        !approval_sentinel.exists(),
        "approval-required task's command must never spawn without approval"
    );
}
