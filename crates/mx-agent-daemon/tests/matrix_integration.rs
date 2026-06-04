//! Local Matrix integration test (issue #60).
//!
//! Exercises the daemon's real Matrix code paths — login, session restore, the
//! long-lived `/sync` loop, sync-token persistence, and event delivery —
//! against a live, throwaway homeserver rather than mocks.
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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use matrix_sdk::ruma::api::client::room::{create_room, Visibility};
use matrix_sdk::ruma::events::room::message::{
    OriginalSyncRoomMessageEvent, RoomMessageEventContent,
};

use mx_agent_daemon::session::ENV_DATA_DIR;
use mx_agent_daemon::{
    load_sync_token, login_password, restore_client, run_matrix_sync, BackoffConfig, MatrixConfig,
    SessionPaths, SyncHealth, SyncState,
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
