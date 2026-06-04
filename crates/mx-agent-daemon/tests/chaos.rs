//! Reconnect, replay, and rate-limit chaos tests (issue #62).
//!
//! These tests subject the daemon's *persisted* state and *streaming* paths to
//! adverse conditions — a restart, duplicate/replayed privileged events, and a
//! noisy command that gaps and floods its output — and assert the two
//! production-hardening acceptance criteria:
//!
//! 1. **The daemon recovers expected state after a restart.** A restart is
//!    modelled faithfully: every in-memory handle is dropped and the state is
//!    reloaded from the same daemon-owned data directory. The reloaded daemon
//!    must keep its stable signing identity, its trust decisions, its resumable
//!    sync position, and its replay protection.
//! 2. **Replayed privileged requests remain denied.** A signed `exec` request
//!    that authorizes once is denied on every replay — and the denial survives a
//!    restart, because the replay cache is persisted. Authorization alone is
//!    stateless and cannot stop replays; the nonce cache is what does.
//!
//! Unlike `tests/matrix_integration.rs`, these tests need no live homeserver:
//! they drive the daemon's real persistence and capture APIs directly, so they
//! run as part of the default `cargo test --all` and guard these properties in
//! CI. This mirrors how the underlying subsystems are validated by unit tests
//! rather than over a real Matrix transport.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use mx_agent_daemon::{
    authorize_exec_request, build_signed_exec_request, capture_child_output, capture_stream,
    load_or_create_signing_key, load_sync_token, run_sync_loop, save_sync_token, BackoffConfig,
    ExecRequestOptions, OutputCaps, ReplayCache, ReplayError, SessionPaths, StreamCaptureConfig,
    SyncHealth, TrustStore,
};
use mx_agent_policy::Policy;
use mx_agent_protocol::schema::{StreamChunk, StreamKind};

/// App-level identity of the agent issuing the privileged requests.
const REQUESTER_AGENT: &str = "@requester:mx-agent.test";
/// App-level identity of the daemon that must run (or refuse) the request.
const TARGET_AGENT: &str = "developer-pi";
/// A room the receive-side policy trusts.
const ROOM_ID: &str = "!chaos:mx-agent.test";

/// A unique, throwaway data directory so persisted state for one test never
/// collides with another run or a real install. Built directly (not via
/// `SessionPaths::resolve()`) so the tests never mutate the process environment
/// and cannot race each other.
fn throwaway_paths(tag: &str) -> SessionPaths {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "mx-agent-chaos-{}-{}-{}-{}",
        tag,
        std::process::id(),
        nanos,
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
    SessionPaths {
        session_file: dir.join("session.json"),
        sync_token_file: dir.join("sync_token"),
        data_dir: dir,
    }
}

/// A receive-side policy that trusts `ROOM_ID` and permits the requester to run
/// the `cargo` exec exercised here, mirroring the exec unit-test fixtures.
fn permissive_policy() -> Policy {
    let toml = format!(
        r#"
[rooms."{ROOM_ID}"]
trusted = true

[rooms."{ROOM_ID}".agents."{REQUESTER_AGENT}"]
allow_exec = true
allow_commands = ["cargo"]
allow_cwd = ["/home/me/code/project"]
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

/// Drain every chunk from a capture into a Vec.
async fn collect(mut rx: mpsc::Receiver<StreamChunk>) -> Vec<StreamChunk> {
    let mut chunks = Vec::new();
    while let Some(chunk) = rx.recv().await {
        chunks.push(chunk);
    }
    chunks
}

/// Assert a single stream's chunks are well-formed regardless of where the
/// producer gapped: per-stream sequence numbers are contiguous from zero and the
/// final chunk is the EOF marker, so a consumer can always detect a clean end.
fn assert_terminated_and_monotonic_refs(chunks: &[&StreamChunk]) {
    assert!(
        !chunks.is_empty(),
        "capture must emit at least an EOF marker"
    );
    let seqs: Vec<u64> = chunks.iter().map(|c| c.seq).collect();
    let expected: Vec<u64> = (0..chunks.len() as u64).collect();
    assert_eq!(seqs, expected, "sequence numbers must be contiguous from 0");
    assert!(
        chunks.last().unwrap().eof,
        "the stream must be terminated by a final EOF marker"
    );
    assert!(
        chunks[..chunks.len() - 1].iter().all(|c| !c.eof),
        "only the final chunk may be the EOF marker"
    );
}

/// Acceptance criterion 1: the daemon recovers its expected state after a
/// restart.
///
/// A restart is modelled by persisting every piece of daemon-owned state, then
/// dropping all in-memory handles and reloading from the same data directory —
/// exactly what a real process restart sees. The reloaded daemon must keep:
///
/// - a **stable signing identity** (same `key_id`), so peers still recognise it;
/// - its **trust decisions**, so a previously approved key stays trusted;
/// - a **resumable sync position**, so `/sync` continues from the stored batch
///   token (reported as `resumed_from_token`); and
/// - its **replay protection**, so a nonce seen before the restart is still
///   known afterwards.
#[tokio::test]
async fn daemon_recovers_expected_state_after_restart() {
    let paths = throwaway_paths("restart");
    paths.ensure_data_dir().expect("create data dir");

    // ---- First boot: establish and persist all daemon state. ----
    let key_id_before;
    let fingerprint_before;
    {
        let signing = load_or_create_signing_key(&paths).expect("create signing key");
        key_id_before = signing.key_id();
        fingerprint_before = signing.fingerprint();

        let mut trust = TrustStore::load(&paths).expect("load trust store");
        trust.approve(REQUESTER_AGENT, &key_id_before, None, None, None);
        trust.save(&paths).expect("persist trust store");

        save_sync_token(&paths, "batch_token_before_restart").expect("persist sync token");

        let mut replay = ReplayCache::load(&paths).expect("load replay cache");
        replay
            .admit_at("pre-restart-nonce", "2099-01-01T00:00:00Z", 100)
            .expect("first admission succeeds");
    }

    // ---- Restart: nothing in memory survives; reload from disk only. ----
    let signing = load_or_create_signing_key(&paths).expect("reload signing key");
    assert_eq!(
        signing.key_id(),
        key_id_before,
        "signing identity must be stable across a restart"
    );
    assert_eq!(
        signing.fingerprint(),
        fingerprint_before,
        "signing fingerprint must be stable across a restart"
    );

    let trust = TrustStore::load(&paths).expect("reload trust store");
    assert!(
        trust.is_trusted(REQUESTER_AGENT, &key_id_before),
        "a previously approved key must remain trusted after a restart"
    );

    // The persisted batch token drives a resumed `/sync`: the loop reports
    // `resumed_from_token` and hands the stored token to its first step.
    assert_eq!(
        load_sync_token(&paths).expect("read sync token").as_deref(),
        Some("batch_token_before_restart"),
        "the resumable sync position must survive a restart"
    );

    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let running = Arc::new(AtomicBool::new(true));
    let first_token: Arc<Mutex<Option<Option<String>>>> = Arc::new(Mutex::new(None));
    {
        let first_token = first_token.clone();
        let running_step = running.clone();
        run_sync_loop(
            &paths,
            health.clone(),
            BackoffConfig::default(),
            running.clone(),
            move |token| {
                let first_token = first_token.clone();
                let running = running_step.clone();
                async move {
                    *first_token.lock().unwrap() = Some(token);
                    running.store(false, Ordering::SeqCst);
                    Ok("batch_token_after_restart".to_string())
                }
            },
        )
        .await
        .expect("sync loop runs");
    }
    assert_eq!(
        first_token.lock().unwrap().clone().flatten().as_deref(),
        Some("batch_token_before_restart"),
        "the restarted sync loop must resume from the stored batch token"
    );
    assert!(
        health.lock().unwrap().resumed_from_token,
        "health must report that the loop resumed from a persisted token"
    );

    // Replay protection persisted too: the pre-restart nonce is still known.
    let mut replay = ReplayCache::load(&paths).expect("reload replay cache");
    assert_eq!(
        replay.admit_at("pre-restart-nonce", "2099-01-01T00:00:00Z", 100),
        Err(ReplayError::Replayed),
        "a nonce seen before the restart must remain known afterwards"
    );
}

/// Acceptance criterion 2: replayed privileged requests remain denied, even
/// across a restart.
///
/// A single signed `exec` request is authorized once, its nonce admitted, then
/// the *identical* request is replayed. The replay must be denied — and it must
/// stay denied after the replay cache is reloaded from disk (a restart). The
/// test also shows that authorization is stateless: the replayed request still
/// passes `authorize_exec_request`, so it is the persisted nonce cache, not the
/// signature/trust/policy checks, that defeats the replay.
#[tokio::test]
async fn replayed_privileged_request_remains_denied_across_restart() {
    let paths = throwaway_paths("replay");
    paths.ensure_data_dir().expect("create data dir");

    let signing = load_or_create_signing_key(&paths).expect("signing key");
    let key_id = signing.key_id();
    let verifying = signing.verifying_key();
    let mut trust = TrustStore::default();
    trust.approve(REQUESTER_AGENT, &key_id, None, None, None);
    let policy = permissive_policy();

    // A signed, well-formed privileged request the daemon would normally run.
    let content = build_signed_exec_request(
        signing.signing_key(),
        &key_id,
        "inv_replay",
        "req_replay",
        "chaos-replay-nonce",
        "2099-01-01T00:00:00Z",
        "2099-01-01T00:05:00Z",
        &exec_options(),
    )
    .expect("sign exec request");

    // First delivery: authorization passes and the nonce is admitted once.
    let authorized = authorize_exec_request(
        &content,
        &verifying,
        &trust,
        &policy,
        ROOM_ID,
        REQUESTER_AGENT,
        TARGET_AGENT,
    )
    .expect("a fresh, signed request authorizes");
    assert_eq!(authorized.invocation_id, "inv_replay");

    let mut replay = ReplayCache::load(&paths).expect("load replay cache");
    replay
        .admit(&authorized.nonce, &authorized.expires_at)
        .expect("the first delivery of a nonce is admitted");

    // Replay the identical event. Authorization is stateless, so it still
    // succeeds — but the replay cache denies the duplicate nonce.
    let reauthorized = authorize_exec_request(
        &content,
        &verifying,
        &trust,
        &policy,
        ROOM_ID,
        REQUESTER_AGENT,
        TARGET_AGENT,
    )
    .expect("the signature is still valid on replay; authorization is stateless");
    assert_eq!(
        replay.admit(&reauthorized.nonce, &reauthorized.expires_at),
        Err(ReplayError::Replayed),
        "a replayed privileged request must be denied by the nonce cache"
    );

    // Restart: reload the replay cache from disk. The replay must stay denied.
    let mut reloaded = ReplayCache::load(&paths).expect("reload replay cache");
    assert_eq!(
        reloaded.admit(&authorized.nonce, &authorized.expires_at),
        Err(ReplayError::Replayed),
        "a replayed privileged request must remain denied after a restart"
    );

    // A privileged request that has expired is also denied, without recording a
    // nonce — a stale replay cannot grow or evict the cache.
    let expired = build_signed_exec_request(
        signing.signing_key(),
        &key_id,
        "inv_expired",
        "req_expired",
        "chaos-expired-nonce",
        "1970-01-01T00:00:00Z",
        "1970-01-01T00:00:10Z",
        &exec_options(),
    )
    .expect("sign expired exec request");
    let expired_req = authorize_exec_request(
        &expired,
        &verifying,
        &trust,
        &policy,
        ROOM_ID,
        REQUESTER_AGENT,
        TARGET_AGENT,
    )
    .expect("an expired request can still carry a valid signature");
    assert_eq!(
        reloaded.admit_at(&expired_req.nonce, &expired_req.expires_at, 20),
        Err(ReplayError::Expired),
        "an expired privileged request must be denied"
    );
}

/// Scope: simulate stream gaps. A producer that goes quiet mid-stream (a gap
/// long enough to trip the flush interval) and then resumes must still have all
/// its output forwarded, with monotonic per-stream sequence numbers and a clean
/// EOF terminator — so a consumer never mistakes a gap for the end of output.
#[tokio::test(start_paused = true)]
async fn stream_survives_a_gap_and_still_terminates() {
    let (tx, rx) = mpsc::channel(64);
    let (mut writer, reader) = tokio::io::duplex(1024);
    let config = StreamCaptureConfig {
        max_chunk_bytes: 1024,
        flush_interval: Duration::from_millis(50),
        flush_on_newline: false,
        caps: OutputCaps::unlimited(),
    };
    let capture = tokio::spawn(async move {
        capture_stream(reader, "inv_gap", StreamKind::Stdout, config, tx).await
    });

    // Output before the gap.
    writer.write_all(b"before-gap").await.expect("write 1");
    // Go quiet long enough for the flush interval to elapse with no new data:
    // this is the stream gap. Paused time auto-advances while the test sleeps.
    tokio::time::sleep(Duration::from_millis(150)).await;
    // Output resumes after the gap.
    writer.write_all(b"after-gap").await.expect("write 2");
    tokio::time::sleep(Duration::from_millis(150)).await;
    // The producer exits, closing the stream (EOF).
    drop(writer);
    capture.await.expect("capture task joins");

    let chunks = collect(rx).await;
    let refs: Vec<&StreamChunk> = chunks.iter().collect();
    assert_terminated_and_monotonic_refs(&refs);
    let payload: String = chunks
        .iter()
        .filter(|c| !c.eof)
        .map(|c| c.data.clone())
        .collect();
    assert_eq!(
        payload, "before-gapafter-gap",
        "all output must be forwarded across the gap"
    );
}

/// Scope: simulate rate limits (event rate). A command emitting many tiny chunks
/// is throttled to the configured events/sec by the shared token bucket, so it
/// cannot flood the Matrix timeline; the stream is still terminated and not
/// flagged as truncated.
#[tokio::test(start_paused = true)]
async fn event_rate_limit_throttles_a_flooding_command() {
    let (tx, mut rx) = mpsc::channel(256);
    let data = [b'a'; 8];
    let config = StreamCaptureConfig {
        max_chunk_bytes: 1,
        ..StreamCaptureConfig::batch()
    }
    .with_caps(OutputCaps {
        max_output_bytes: None,
        max_events_per_second: Some(2),
    });
    let handle = tokio::spawn(async move {
        capture_child_output(&data[..], &[][..], "inv_rate", config, tx).await
    });

    // The token bucket starts full (capacity == rate == 2), so only the initial
    // burst may emit before virtual time advances; the rest must wait.
    tokio::time::sleep(Duration::from_millis(10)).await;
    let mut burst = 0usize;
    while let Ok(chunk) = rx.try_recv() {
        if !chunk.eof {
            burst += 1;
        }
    }
    assert!(
        burst <= 2,
        "rate limit must hold emission to the initial burst, got {burst}"
    );

    // Advance virtual time so the bucket refills and the rest drains.
    tokio::time::advance(Duration::from_secs(10)).await;
    let mut chunks = Vec::new();
    while let Some(chunk) = rx.recv().await {
        chunks.push(chunk);
    }
    let summary = handle.await.expect("capture task joins");
    assert!(!summary.truncated, "rate limiting must not drop output");
    assert!(
        chunks.iter().any(|c| c.eof),
        "the throttled stream must still be terminated"
    );
}

/// Scope: simulate rate limits (output volume). A high-output command is capped
/// to a per-invocation byte budget: output beyond the budget is dropped, the
/// summary is flagged truncated, and the stream is still cleanly terminated so a
/// consumer is never left waiting on a missing end-of-stream.
#[tokio::test]
async fn output_byte_cap_truncates_a_flooding_command() {
    let (tx, rx) = mpsc::channel(256);
    let data = vec![b'x'; 64 * 1024];
    let config = StreamCaptureConfig::batch().with_caps(OutputCaps {
        max_output_bytes: Some(4096),
        max_events_per_second: None,
    });
    let summary = capture_child_output(&data[..], &[][..], "inv_cap", config, tx).await;
    let chunks = collect(rx).await;

    let forwarded: usize = chunks.iter().map(|c| c.data.len()).sum();
    assert!(
        forwarded <= 4096,
        "forwarded {forwarded} bytes, cap was 4096"
    );
    assert!(summary.truncated, "summary must report truncation");
    assert_eq!(summary.output_bytes, 4096);
    // Both streams (stdout and the empty stderr) must still be terminated, so a
    // consumer is never left waiting past the cap. Each stream carries its own
    // monotonic sequence counter, so the EOF marker is checked per stream.
    for stream in [StreamKind::Stdout, StreamKind::Stderr] {
        let per_stream: Vec<&StreamChunk> = chunks.iter().filter(|c| c.stream == stream).collect();
        assert_terminated_and_monotonic_refs(&per_stream);
    }
}
