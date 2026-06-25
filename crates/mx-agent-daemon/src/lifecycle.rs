//! Daemon process lifecycle: start (foreground/background), status, and stop.
//!
//! State is tracked with a small JSON status file under the runtime directory
//! (see `docs/architecture.md`, section 10). The Unix socket itself is created
//! in a later phase; this module only records its intended path.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mx_agent_ipc::rpc::{Request, Response, INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use crate::session::{load_session, SessionPaths, StoredSession};
use crate::sync::{BackoffConfig, SyncHealth};
use crate::DaemonInfo;

/// Shared, optional sync-loop health surfaced through `daemon.status`.
///
/// `None` means the sync loop is not running (e.g. no Matrix session yet);
/// otherwise the inner handle is the live health updated by the sync loop.
type SharedHealth = Option<Arc<Mutex<SyncHealth>>>;

/// Version reported by the daemon, taken from the crate version.
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Environment variable overriding the runtime directory (useful for tests).
pub const ENV_RUNTIME_DIR: &str = "MX_AGENT_RUNTIME_DIR";

/// Resolved filesystem locations used by the daemon.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Directory holding the daemon's runtime state.
    pub runtime_dir: PathBuf,
    /// JSON status file describing the running daemon.
    pub status_file: PathBuf,
    /// Intended Unix domain socket path.
    pub socket_path: PathBuf,
    /// Log file used when the daemon runs in the background.
    pub log_file: PathBuf,
}

impl Paths {
    /// Resolve runtime paths from the environment.
    ///
    /// Precedence: `MX_AGENT_RUNTIME_DIR`, then `$XDG_RUNTIME_DIR/mx-agent`,
    /// then a temp-directory fallback.
    pub fn resolve() -> Self {
        let runtime_dir = if let Ok(dir) = std::env::var(ENV_RUNTIME_DIR) {
            PathBuf::from(dir)
        } else if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(xdg).join("mx-agent")
        } else {
            std::env::temp_dir().join("mx-agent")
        };
        Self {
            status_file: runtime_dir.join("daemon.json"),
            socket_path: runtime_dir.join("daemon.sock"),
            log_file: runtime_dir.join("daemon.log"),
            runtime_dir,
        }
    }

    /// Ensure the runtime directory exists, creating it with `0700` permissions.
    ///
    /// An existing directory is left untouched so that unsafe permissions are
    /// surfaced (and refused) at socket-bind time rather than silently widened
    /// or narrowed.
    pub fn ensure_runtime_dir(&self) -> io::Result<()> {
        if !self.runtime_dir.exists() {
            fs::create_dir_all(&self.runtime_dir)?;
            fs::set_permissions(&self.runtime_dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

/// Persisted contents of the daemon status file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StatusFile {
    pid: u32,
    started_at_unix: u64,
    socket_path: String,
    version: String,
}

/// A snapshot of a running daemon, suitable for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningStatus {
    /// Always `true`; present so JSON output is self-describing.
    pub running: bool,
    /// Process ID of the daemon.
    pub pid: u32,
    /// Seconds elapsed since the daemon started.
    pub uptime_seconds: u64,
    /// Intended Unix socket path.
    pub socket_path: String,
    /// Daemon version.
    pub version: String,
    /// Matrix sync-loop health, if the sync loop is running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync: Option<SyncHealth>,
    /// Operator-policy health. Present only when the policy file is unusable
    /// (malformed); omitted for a healthy or absent policy, keeping the payload
    /// backward-compatible (issue #350).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::policy::PolicyStatus>,
}

impl RunningStatus {
    /// Render the status as a single-line JSON object.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{\"running\":true}".to_string())
    }
}

/// Outcome of a [`stop`] request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    /// No daemon was running.
    NotRunning,
    /// The daemon exited after `SIGTERM`.
    Stopped(u32),
    /// The daemon had to be force-killed with `SIGKILL`.
    Killed(u32),
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns true if a process with `pid` currently exists.
fn is_alive(pid: u32) -> bool {
    // Ok means the process exists; EPERM means it exists but we may not signal
    // it; anything else (notably ESRCH) means it is gone.
    matches!(
        kill(Pid::from_raw(pid as i32), None),
        Ok(()) | Err(nix::errno::Errno::EPERM)
    )
}

fn read_status_file(paths: &Paths) -> io::Result<Option<StatusFile>> {
    match fs::read(&paths.status_file) {
        Ok(bytes) => match serde_json::from_slice::<StatusFile>(&bytes) {
            Ok(status) => Ok(Some(status)),
            Err(_) => Ok(None),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn write_status_file(paths: &Paths, status: &StatusFile) -> io::Result<()> {
    paths.ensure_runtime_dir()?;
    let tmp = paths.status_file.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(status)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    {
        let mut f = fs::File::create(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(&bytes)?;
        f.flush()?;
    }
    fs::rename(&tmp, &paths.status_file)?;
    Ok(())
}

fn remove_status_file(paths: &Paths) {
    let _ = fs::remove_file(&paths.status_file);
}

/// Return the status of the running daemon, if any.
///
/// A stale status file (referencing a dead process) is removed and treated as
/// "not running".
pub fn status() -> io::Result<Option<RunningStatus>> {
    let paths = Paths::resolve();
    let Some(sf) = read_status_file(&paths)? else {
        return Ok(None);
    };
    if !is_alive(sf.pid) {
        remove_status_file(&paths);
        return Ok(None);
    }
    let uptime = now_unix().saturating_sub(sf.started_at_unix);
    Ok(Some(RunningStatus {
        running: true,
        pid: sf.pid,
        uptime_seconds: uptime,
        socket_path: sf.socket_path,
        version: sf.version,
        // The on-disk status file does not carry live sync health; the live
        // value is obtained from the running daemon over IPC.
        sync: None,
        // Likewise, policy health is resolved fresh on the live IPC path (which
        // the CLI prefers); the on-disk fallback has no live view (issue #350).
        policy: None,
    }))
}

/// Run the daemon in the foreground until `SIGINT`/`SIGTERM`.
///
/// Writes the status file on startup and removes it on shutdown.
pub fn run_foreground() -> io::Result<()> {
    let paths = Paths::resolve();
    paths.ensure_runtime_dir()?;

    // Refuse to start on a present-but-unusable policy (issue #350). An absent
    // policy is the intended deny-all default and starts normally; a malformed
    // one would otherwise deny everything silently the moment a request arrives.
    // This gate is authoritative — it also covers a direct `daemon start
    // --foreground` and a TOCTOU edit between the `start_background` pre-check and
    // this spawn. Policy is independent of the Matrix session, so the gate runs
    // unconditionally (even before login).
    if let crate::policy::PolicyResolution::Malformed {
        path,
        display: detail,
    } = crate::policy::resolve_policy()
    {
        tracing::error!(
            path = %path.display(),
            error = %detail,
            "refusing to start: policy file is present but unusable; fix or remove it"
        );
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed policy {}: {detail}", path.display()),
        ));
    }

    let mut signals = Signals::new([SIGINT, SIGTERM])?;

    // Bind the IPC socket before announcing readiness. The guard unlinks the
    // socket on shutdown. Binding validates that the runtime directory is
    // private to the current user.
    let socket = mx_agent_ipc::bind(&paths.socket_path)?;

    let pid = std::process::id();
    let started_at = now_unix();
    let socket_path = paths.socket_path.to_string_lossy().into_owned();
    let status = StatusFile {
        pid,
        started_at_unix: started_at,
        socket_path: socket_path.clone(),
        version: DAEMON_VERSION.to_string(),
    };
    write_status_file(&paths, &status)?;

    // Restart janitor: reap any exec child process groups left alive by a
    // previous daemon run (a crash or a force-kill that never ran the graceful
    // teardown) before starting fresh work (issue #316).
    crate::exec::reap_orphaned_live_exec_children(&SessionPaths::resolve());

    // Start the Matrix sync loop if a session is present. The supervisor owns the
    // current worker generation (sync + scheduler + heartbeat) and its shared
    // health, so `daemon.status` reports live progress and a post-start
    // `auth login` can bring the workers up via `session.reload` without a daemon
    // restart (issue #316). When a session is present the same restored client
    // drives the live task scheduler loop (architecture §9.2, issue #199).
    let exec_subscribers = crate::ExecSubscriberRegistry::new();
    let supervisor = WorkerSupervisor::new(exec_subscribers.clone());
    supervisor.ensure_started();

    // Serve IPC requests on a background thread. The thread is torn down when
    // the process exits after shutdown.
    let listener = socket.listener().try_clone()?;
    let handler_socket = socket_path.clone();
    let handler_supervisor = supervisor.clone();
    let _server = std::thread::spawn(move || {
        let handler = move |req: &Request, stream: &mut std::os::unix::net::UnixStream| {
            dispatch_streaming(
                req,
                stream,
                pid,
                started_at,
                &handler_socket,
                &handler_supervisor,
                &exec_subscribers,
            )
        };
        if let Err(e) = mx_agent_ipc::serve_streaming(&listener, handler) {
            tracing::warn!(error = %e, "ipc server stopped");
        }
    });

    DaemonInfo::new().log_summary();
    tracing::info!(pid, socket = %socket_path, "daemon started (foreground)");

    if let Some(signal) = signals.forever().next() {
        tracing::info!(signal, "received shutdown signal");
    }

    // Tear down in-flight exec child process groups before winding down the
    // workers, so the common `daemon stop` path never orphans them when their
    // owning runtime is dropped (issue #316). The SIGTERM→SIGKILL grace is kept
    // well under `daemon stop`'s own 5s grace so this graceful teardown finishes
    // before `stop` would escalate to SIGKILLing the daemon.
    crate::exec::terminate_live_exec_children(&SessionPaths::resolve(), Duration::from_secs(2));

    // Signal the sync, scheduler, and heartbeat loops to stop, wait for them to
    // wind down, and drop the shared client so a later in-process run restores a
    // fresh one.
    supervisor.wind_down();

    remove_status_file(&paths);
    drop(socket);
    tracing::info!(pid, "daemon stopped");
    Ok(())
}

/// Type alias for the trio of background worker threads (sync + scheduler +
/// heartbeat).
type WorkerThreads = (
    Option<std::thread::JoinHandle<()>>,
    Option<std::thread::JoinHandle<()>>,
    Option<std::thread::JoinHandle<()>>,
);

/// Spawn the Matrix sync loop, the live task scheduler loop, and the periodic
/// heartbeat loop, if a session is stored, sharing one restored client between
/// them.
///
/// Returns `((None, None, None), None)` (and does nothing) when no Matrix
/// session exists yet, so the daemon runs cleanly before login. The sync thread
/// owns a current-thread Tokio runtime that drives
/// [`crate::sync::run_matrix_sync`]; the scheduler thread owns its own runtime
/// and drives [`crate::run_scheduler_loop`]; the heartbeat thread owns its own
/// runtime and drives [`crate::run_heartbeat_loop`]. Only the sync loop advances
/// the session token — the scheduler and heartbeat loops read cached state and
/// send events over the same client, so there is no token race (architecture
/// §9.1/§9.2, issues #199/#250).
fn spawn_matrix_workers(
    running: Arc<AtomicBool>,
    exec_subscribers: crate::ExecSubscriberRegistry,
) -> (WorkerThreads, SharedHealth) {
    let session_paths = SessionPaths::resolve();
    let session = match load_session(&session_paths) {
        Ok(Some(session)) => session,
        Ok(None) => {
            tracing::info!(
                "no Matrix session stored; sync, scheduler, and heartbeat loops not started"
            );
            return ((None, None, None), None);
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not load Matrix session; sync, scheduler, and heartbeat loops not started");
            return ((None, None, None), None);
        }
    };

    // The health handle is created up front and shared with the IPC handler so
    // status reflects the loop's progress live. The restored client is published
    // into a shared slot so the scheduler thread can share it without opening a
    // second client (which would race on the session token).
    let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
    let shared_client: Arc<Mutex<Option<matrix_sdk::Client>>> = Arc::new(Mutex::new(None));
    let loop_health = health.clone();
    let sync_running = running.clone();
    // On any non-shutdown sync exit (fatal auth error, persistence error, or a
    // failed restore) the sync thread clears the shared generation flag so the
    // scheduler and heartbeat loops — which watch the same flag — wind down with
    // it, leaving the daemon idle but alive (still serving IPC, recoverable via
    // re-login + `session.reload`) instead of running on a dead-token client
    // (issue #316). On a graceful shutdown the flag is already clear, so this is
    // a no-op.
    let sync_wind_down = running.clone();
    let publish_client = shared_client.clone();
    // The scheduler shares the registry the sync loop forwards Matrix exec
    // results into, so Matrix-backed task dispatch can await those results.
    let exec_subscribers_for_scheduler = exec_subscribers.clone();
    let sync_handle = std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!(error = %e, "failed to build sync runtime");
                return;
            }
        };
        runtime.block_on(async move {
            let client = match crate::matrix::restore_client(&session).await {
                Ok(client) => client,
                Err(e) => {
                    tracing::error!(error = %e, "failed to restore Matrix session for sync");
                    loop_health
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_fatal(e.to_string());
                    return;
                }
            };
            *publish_client.lock().unwrap_or_else(|e| e.into_inner()) = Some(client.clone());
            // Publish the one restored client process-wide so per-call IPC
            // handlers reuse it (one OlmMachine on the persistent crypto store)
            // instead of each opening a second store-backed client (issue #240).
            crate::matrix::publish_active_client(client.clone());
            if let Err(e) = crate::sync::run_matrix_sync_with_subscribers(
                &client,
                &SessionPaths::resolve(),
                loop_health,
                BackoffConfig::default(),
                sync_running,
                Some(exec_subscribers),
            )
            .await
            {
                tracing::warn!(error = %e, "sync loop exited with error");
            }
        });
        // Wind down the rest of the generation if the loop stopped for any
        // reason other than a requested shutdown (issue #316).
        sync_wind_down.store(false, Ordering::SeqCst);
    });

    // The heartbeat thread shares the same restored client (waiting on the same
    // shared slot) and the shutdown flag, so it stops cleanly with the others and
    // never opens a second client. Clone before the scheduler closure consumes
    // the originals.
    let heartbeat_client = shared_client.clone();
    let heartbeat_running = running.clone();

    // Task dispatch defaults to local in-process execution; opt into the signed
    // Matrix-backed `call`/`exec` transport with `MX_AGENT_TASK_DISPATCH=matrix`
    // (issue #200). The scheduler shares the daemon's exec subscriber registry so
    // Matrix exec results forwarded by the sync loop reach the dispatcher.
    let dispatch_mode = crate::TaskDispatchMode::from_env();
    let scheduler_subscribers = exec_subscribers_for_scheduler;
    let scheduler_handle = std::thread::spawn(move || {
        // Wait for the sync thread to publish the restored client (or for
        // shutdown), then drive the scheduler loop over the same client.
        let client = loop {
            if !running.load(Ordering::SeqCst) {
                return;
            }
            if let Some(client) = shared_client
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
            {
                break client;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        crate::run_scheduler_loop(
            client,
            scheduler_subscribers,
            dispatch_mode,
            running,
            crate::DEFAULT_SCHEDULER_INTERVAL,
        );
    });

    // The heartbeat thread refreshes liveness for every agent this daemon owns at
    // `DEFAULT_HEARTBEAT_INTERVAL`, so a long-running agent's `last_seen_ts` and
    // heartbeat timeline event stay fresh and peers compute `active` rather than
    // drifting to `stale`/`offline` (issue #250).
    let heartbeat_handle = std::thread::spawn(move || {
        let client = loop {
            if !heartbeat_running.load(Ordering::SeqCst) {
                return;
            }
            if let Some(client) = heartbeat_client
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
            {
                break client;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        crate::run_heartbeat_loop(
            client,
            heartbeat_running,
            crate::HeartbeatConfig::default(),
            crate::DEFAULT_HEARTBEAT_INTERVAL,
        );
    });

    let threads: WorkerThreads = (
        Some(sync_handle),
        Some(scheduler_handle),
        Some(heartbeat_handle),
    );
    (threads, Some(health))
}

/// The current generation of background workers owned by a [`WorkerSupervisor`].
struct WorkerGeneration {
    /// The generation's shutdown flag, shared with all three loops. `None` when
    /// no workers are running.
    running: Option<Arc<AtomicBool>>,
    /// The generation's live sync health, surfaced through `daemon.status`.
    health: SharedHealth,
    /// Join handles for the sync, scheduler, and heartbeat threads.
    threads: WorkerThreads,
}

/// Owns the daemon's background worker generation (sync + scheduler + heartbeat)
/// behind a shared handle, so the IPC handler and the shutdown path can start,
/// reload, and inspect it (issue #316).
///
/// Lifting worker state into a supervisor lets a post-start `auth login` bring
/// the loops up without a daemon restart (via the `session.reload` IPC method),
/// makes `daemon.status` reflect a sync loop that started *after* daemon start,
/// and gives the fatal-stop wind-down a single place to reload a fresh
/// generation. Clones share one inner generation (`Arc<Mutex<…>>`).
#[derive(Clone)]
struct WorkerSupervisor {
    inner: Arc<Mutex<WorkerGeneration>>,
    exec_subscribers: crate::ExecSubscriberRegistry,
}

impl WorkerSupervisor {
    /// Create a supervisor with no workers running yet.
    fn new(exec_subscribers: crate::ExecSubscriberRegistry) -> Self {
        Self {
            inner: Arc::new(Mutex::new(WorkerGeneration {
                running: None,
                health: None,
                threads: (None, None, None),
            })),
            exec_subscribers,
        }
    }

    /// The current generation's sync health, for `daemon.status`. `None` when no
    /// workers are running (e.g. before first login).
    fn health(&self) -> SharedHealth {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .health
            .clone()
    }

    /// Spawn the workers if none run and a session exists; no-op otherwise.
    ///
    /// Returns whether workers are running afterwards (`false` only when there is
    /// still no stored session to start them for).
    fn ensure_started(&self) -> bool {
        let mut gen = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if gen.running.is_some() {
            return true;
        }
        let running = Arc::new(AtomicBool::new(true));
        let (threads, health) =
            spawn_matrix_workers(running.clone(), self.exec_subscribers.clone());
        if health.is_none() {
            // No session: nothing was spawned. Stay idle.
            return false;
        }
        gen.running = Some(running);
        gen.health = health;
        gen.threads = threads;
        true
    }

    /// Wind down the current generation: clear its flag, join its threads, and
    /// drop the shared client so a later restore is fresh.
    fn wind_down(&self) {
        let (running, threads) = {
            let mut gen = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let running = gen.running.take();
            let threads = std::mem::take(&mut gen.threads);
            gen.health = None;
            (running, threads)
        };
        if let Some(running) = running {
            running.store(false, Ordering::SeqCst);
        }
        // Join outside the lock so a worker that touches the supervisor cannot
        // deadlock against the wind-down.
        let (sync_thread, scheduler_thread, heartbeat_thread) = threads;
        if let Some(handle) = sync_thread {
            let _ = handle.join();
        }
        if let Some(handle) = scheduler_thread {
            let _ = handle.join();
        }
        if let Some(handle) = heartbeat_thread {
            let _ = handle.join();
        }
        crate::matrix::clear_active_client();
    }

    /// Wind down the current generation and start a fresh one (used by
    /// `session.reload` and a post-login reload). Returns `(started, logged_in)`.
    fn reload(&self) -> (bool, bool) {
        self.wind_down();
        let started = self.ensure_started();
        let logged_in = load_session(&SessionPaths::resolve())
            .map(|s| s.is_some())
            .unwrap_or(false);
        (started, logged_in)
    }
}

fn write_ipc_response(
    stream: &mut std::os::unix::net::UnixStream,
    response: &Response,
) -> io::Result<()> {
    let encoded = serde_json::to_vec(response).unwrap_or_else(|_| {
        br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"encode failure"}}"#
            .to_vec()
    });
    mx_agent_ipc::write_frame(stream, &encoded)
}

fn parse_params<T>(req: &Request) -> Result<T, Box<Response>>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(req.params.clone()).map_err(|e| {
        Box::new(Response::error(
            req.id.clone(),
            INVALID_PARAMS,
            format!("invalid params for {}: {e}", req.method),
        ))
    })
}

fn load_daemon_session_response(req: &Request) -> Result<StoredSession, Box<Response>> {
    match load_session(&SessionPaths::resolve()) {
        Ok(Some(session)) => Ok(session),
        Ok(None) => Err(Box::new(Response::error(
            req.id.clone(),
            INTERNAL_ERROR,
            "not logged in; run `mx-agent auth login` first",
        ))),
        Err(e) => Err(Box::new(Response::error(
            req.id.clone(),
            INTERNAL_ERROR,
            format!("could not read daemon session: {e}"),
        ))),
    }
}

/// Wall-clock ceiling for a single request/response IPC handler's homeserver
/// work, after which the handler is abandoned and a bounded JSON-RPC error is
/// returned instead of hanging the connection (issue #371).
///
/// A handler that does `sync_once` plus an unbounded `/messages` pagination can
/// accumulate matrix-sdk's individually-bounded reads (≈30s each; see
/// `crate::matrix` `SDK_MAX_RETRY_TIME`) into an effectively unbounded total,
/// and because one IPC connection is served serially a stalled handler poisons
/// every request multiplexed behind it (the failure mode that let #368 escape).
/// This default sits ~2× above the SDK's single-request envelope so a slow but
/// *working* read is not false-tripped, while a *stalled* one is bounded.
///
/// Streaming/interactive handlers (`task.watch`, `exec`/`pty`, `call.start`,
/// `device.verify.start`) are intentionally long-lived, do not go through
/// [`block_on_task_response`], and are not bounded here.
const IPC_REQUEST_BUDGET: Duration = Duration::from_secs(60);

/// Larger ceiling for key-backup restore, which legitimately takes longer than a
/// status/list read (server-side backup creation plus room-key download).
const IPC_RECOVERY_BUDGET: Duration = Duration::from_secs(180);

/// Per-method homeserver-read budget (issue #371). Recovery operations get a
/// larger ceiling; everything else uses [`IPC_REQUEST_BUDGET`].
fn request_budget(method: &str) -> Duration {
    match method {
        "recovery.enable" | "recovery.recover" => IPC_RECOVERY_BUDGET,
        _ => IPC_REQUEST_BUDGET,
    }
}

/// Outcome of running a request/response handler future under a wall-clock
/// budget (issue #371).
enum BoundedOutcome<T> {
    /// The handler finished within budget (carrying its own success or error).
    Completed(Result<T, crate::WorkspaceError>),
    /// The handler exceeded the budget and was abandoned.
    TimedOut,
}

/// Run a request/response handler future to completion, or abandon it once
/// `budget` elapses (issue #371).
///
/// On timeout the future is dropped, cancelling any in-flight matrix-sdk read.
/// matrix-sdk reads are cancel-safe: a dropped HTTP request leaves no
/// half-committed local state (crypto-store writes follow successful responses).
async fn run_bounded<T>(
    budget: Duration,
    fut: impl std::future::Future<Output = Result<T, crate::WorkspaceError>>,
) -> BoundedOutcome<T> {
    match tokio::time::timeout(budget, fut).await {
        Ok(result) => BoundedOutcome::Completed(result),
        Err(_) => BoundedOutcome::TimedOut,
    }
}

/// Map a [`BoundedOutcome`] to the JSON-RPC [`Response`] for `req` (issue #371).
///
/// A timeout surfaces as an `INTERNAL_ERROR` (no new wire code) with a
/// distinctive, greppable message and a `warn!` that logs only the method and
/// budget — never request contents or secrets.
fn bounded_response<T: serde::Serialize>(
    req: &Request,
    budget: Duration,
    outcome: BoundedOutcome<T>,
) -> Response {
    match outcome {
        BoundedOutcome::Completed(Ok(value)) => match serde_json::to_value(value) {
            Ok(value) => Response::result(req.id.clone(), value),
            Err(e) => Response::error(req.id.clone(), INTERNAL_ERROR, e.to_string()),
        },
        BoundedOutcome::Completed(Err(e)) => {
            Response::error(req.id.clone(), INTERNAL_ERROR, e.to_string())
        }
        BoundedOutcome::TimedOut => {
            tracing::warn!(
                method = %req.method,
                budget_secs = budget.as_secs(),
                "ipc handler timed out waiting on the homeserver; abandoning (issue #371)"
            );
            Response::error(
                req.id.clone(),
                INTERNAL_ERROR,
                format!(
                    "daemon timed out after {}s waiting on the homeserver while handling {} (issue #371)",
                    budget.as_secs(),
                    req.method
                ),
            )
        }
    }
}

fn block_on_task_response<F, Fut, T>(req: &Request, f: F) -> Response
where
    F: FnOnce(StoredSession) -> Fut,
    Fut: std::future::Future<Output = Result<T, crate::WorkspaceError>>,
    T: serde::Serialize,
{
    let session = match load_daemon_session_response(req) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            return Response::error(
                req.id.clone(),
                INTERNAL_ERROR,
                format!("could not start async runtime: {e}"),
            )
        }
    };
    // Bound the handler's total homeserver work so a stalled `sync_once` /
    // `/messages` read returns a JSON-RPC error instead of hanging — and
    // poisoning — the serially-served connection (issue #371). Streaming
    // handlers bypass this wrapper and stay unbounded by design.
    let budget = request_budget(&req.method);
    let outcome = runtime.block_on(run_bounded(budget, f(session)));
    bounded_response(req, budget, outcome)
}

/// Dispatch a single-response IPC request against the running daemon.
fn dispatch(
    req: &Request,
    pid: u32,
    started_at: u64,
    socket_path: &str,
    supervisor: &WorkerSupervisor,
    exec_subscribers: Option<&crate::ExecSubscriberRegistry>,
) -> Response {
    match req.method.as_str() {
        "daemon.ping" => Response::result(req.id.clone(), json!({"pong": true})),
        // Bring the background workers up (or restart them) against the currently
        // stored session, so a post-start `auth login` starts sync/scheduler/
        // heartbeat without a daemon restart (issue #316).
        "session.reload" => {
            let (started, logged_in) = supervisor.reload();
            Response::result(
                req.id.clone(),
                json!({ "started": started, "logged_in": logged_in }),
            )
        }
        "daemon.status" => {
            let sync = supervisor
                .health()
                .as_ref()
                .map(|h| h.lock().unwrap_or_else(|e| e.into_inner()).clone());
            // Re-resolve the policy fresh so a file broken *after* startup is
            // surfaced persistently here; healthy/absent policies report nothing
            // (issue #350). `daemon.status` is operator-initiated and
            // low-frequency, so re-reading the file on demand is cheap.
            let policy = crate::policy::resolve_policy().status();
            let status = RunningStatus {
                running: true,
                pid,
                uptime_seconds: now_unix().saturating_sub(started_at),
                socket_path: socket_path.to_string(),
                version: DAEMON_VERSION.to_string(),
                sync,
                policy,
            };
            match serde_json::to_value(&status) {
                Ok(value) => Response::result(req.id.clone(), value),
                Err(e) => Response::error(req.id.clone(), INTERNAL_ERROR, e.to_string()),
            }
        }
        "call.start" => match parse_params::<crate::CallStartParams>(req) {
            Ok(params) => dispatch_call_start(req, &params),
            Err(response) => *response,
        },
        "exec.start" => match parse_params::<crate::ExecStartParams>(req) {
            Ok(params) => dispatch_exec_start(req, &params, exec_subscribers),
            Err(response) => *response,
        },
        "exec.stdin" => match parse_params::<crate::ExecStdinParams>(req) {
            Ok(params) => dispatch_exec_stdin(req, &params),
            Err(response) => *response,
        },
        "exec.cancel" => match parse_params::<crate::ExecCancelParams>(req) {
            Ok(params) => dispatch_exec_cancel(req, &params),
            Err(response) => *response,
        },
        "task.create" => match parse_params::<crate::CreateTaskOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::create_task_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        "task.update" => match parse_params::<crate::UpdateTaskOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::update_task_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        "task.list" => match parse_params::<crate::ListTasksOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::list_tasks_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        "task.graph" => match parse_params::<crate::ListTasksOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                let tasks = crate::list_tasks_for_session(&session, &options).await?;
                // Best-effort heartbeat-enriched agent snapshot for agent-dependent
                // diagnostics; when it cannot be read — including a slow/unresponsive
                // homeserver, which the enrichment now bounds with a wall-clock
                // timeout so this handler can never hang and stall the IPC connection
                // (issue #368) — agent checks degrade to durable-only liveness rather
                // than failing the graph query. Using the liveness-enriched path
                // (combined durable + heartbeat verdict) means a healthy, heartbeating
                // agent never reads as inactive between the slower durable-state
                // refreshes (issue #312).
                let listings = crate::list_agents_with_liveness_for_session(
                    &session,
                    &crate::ListAgentsOptions {
                        room: options.room.clone(),
                        capabilities: Vec::new(),
                    },
                )
                .await
                .unwrap_or_default();
                let mut liveness: std::collections::HashMap<String, crate::Liveness> =
                    std::collections::HashMap::with_capacity(listings.len());
                let mut agents = Vec::with_capacity(listings.len());
                for listing in listings {
                    liveness.insert(listing.agent.agent_id.clone(), listing.liveness);
                    agents.push(listing.agent);
                }
                let warnings = crate::diagnose_tasks(&tasks, &agents, &liveness);
                Ok(crate::TaskGraph::from_tasks(&tasks).with_diagnostics(warnings))
            }),
            Err(response) => *response,
        },
        "task.cancel" => match parse_params::<crate::TaskCancelParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                // The daemon owns the signing key and signs the linked
                // invocation's cancel so the target agent can verify the
                // requester before terminating the command (issue #239).
                let signing = crate::load_or_create_signing_key(&SessionPaths::resolve())
                    .map_err(|e| crate::WorkspaceError::Io(io::Error::other(e.to_string())))?;
                let key_id = signing.key_id();
                let reason = params
                    .reason
                    .clone()
                    .unwrap_or_else(|| "cancelled by operator".to_string());
                crate::cancel_task_for_session(
                    &session,
                    signing.signing_key(),
                    &key_id,
                    &params.room,
                    &params.task_id,
                    &reason,
                )
                .await
            }),
            Err(response) => *response,
        },
        // --- workspace (issue #201) ---
        "workspace.create" => match parse_params::<crate::CreateWorkspaceOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::create_workspace_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        "workspace.join" => match parse_params::<crate::RoomParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                crate::join_workspace_for_session(&session, &params.room).await
            }),
            Err(response) => *response,
        },
        "workspace.attach" => match parse_params::<crate::AttachWorkspaceOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::attach_workspace_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        "workspace.grant" => match parse_params::<crate::GrantWorkspaceOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::grant_workspace_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        "workspace.status" => match parse_params::<crate::RoomParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                crate::workspace_status_for_session(&session, &params.room).await
            }),
            Err(response) => *response,
        },
        // --- agent (issue #201) ---
        "agent.register" => match parse_params::<crate::RegisterAgentOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::register_agent_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        "agent.list" => match parse_params::<crate::ListAgentsOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::list_agents_with_liveness_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        "agent.show" => match parse_params::<crate::RoomAgentParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                crate::show_agent_with_liveness_for_session(
                    &session,
                    &params.room,
                    &params.agent_id,
                )
                .await
            }),
            Err(response) => *response,
        },
        "agent.tools" => match parse_params::<crate::RoomAgentParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                crate::agent_tools_for_session(&session, &params.room, &params.agent_id).await
            }),
            Err(response) => *response,
        },
        // --- trust (issue #201) ---
        "trust.publish" => match parse_params::<crate::TrustPublishParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                crate::publish_trust_state_for_session(&session, &params.room, &params.entry).await
            }),
            Err(response) => *response,
        },
        "trust.state" => match parse_params::<crate::RoomParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                crate::list_trust_states_for_session(&session, &params.room).await
            }),
            Err(response) => *response,
        },
        // --- approval (issue #201) ---
        "approval.decide" => match parse_params::<crate::ApprovalDecideParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                let approved_by = params.by.clone().unwrap_or_else(|| session.user_id.clone());
                crate::decide_approval_for_session(
                    &session,
                    &SessionPaths::resolve(),
                    &params.request_id,
                    &params.decision,
                    &approved_by,
                )
                .await
            }),
            Err(response) => *response,
        },
        // --- share (issue #201) ---
        "share.file" => match parse_params::<crate::ShareContextOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::share_context_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        "share.diff" => match parse_params::<crate::ShareDiffOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::share_diff_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        "share.env" => match parse_params::<crate::ShareEnvOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::share_env_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        "share.list" => match parse_params::<crate::ListSharesOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::list_context_shares_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        "share.get" => match parse_params::<crate::FetchContextOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::fetch_context_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        // --- invocation (issue #201) ---
        "invocation.list" => match parse_params::<crate::ListInvocationsOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::list_invocations_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        "invocation.get" => match parse_params::<crate::RoomInvocationParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                crate::get_invocation_for_session(&session, &params.room, &params.invocation_id)
                    .await
            }),
            Err(response) => *response,
        },
        "invocation.cancel" => match parse_params::<crate::InvocationCancelParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                let signing = crate::load_or_create_signing_key(&SessionPaths::resolve())
                    .map_err(|e| crate::WorkspaceError::Io(io::Error::other(e.to_string())))?;
                let key_id = signing.key_id();
                let reason = params
                    .reason
                    .clone()
                    .unwrap_or_else(|| "cancelled by operator".to_string());
                crate::cancel_invocation_for_session(
                    &session,
                    signing.signing_key(),
                    &key_id,
                    &params.room,
                    &params.invocation_id,
                    &reason,
                )
                .await
            }),
            Err(response) => *response,
        },
        "invocation.artifact" => match parse_params::<crate::RetrieveArtifactOptions>(req) {
            Ok(options) => block_on_task_response(req, |session| async move {
                crate::retrieve_artifact_for_session(&session, &options).await
            }),
            Err(response) => *response,
        },
        // --- device verification + cross-signing (issue #240) ---
        "device.list" => match parse_params::<crate::DeviceListParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                crate::list_devices_for_session(&session, &params).await
            }),
            Err(response) => *response,
        },
        "device.show" => match parse_params::<crate::DeviceShowParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                crate::show_device_for_session(&session, &params).await
            }),
            Err(response) => *response,
        },
        "device.verify.manual" => match parse_params::<crate::DeviceVerifyManualParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                crate::manual_verify_for_session(&session, &params).await
            }),
            Err(response) => *response,
        },
        // The interactive SAS decision (confirm/cancel) is delivered in-band as a
        // control frame on the held-open `device.verify.start` connection (see
        // `read_verify_decision`), not as standalone IPC methods.
        "cross_signing.bootstrap" => block_on_task_response(req, |session| async move {
            crate::bootstrap_cross_signing_for_session(&session).await
        }),
        "cross_signing.status" => block_on_task_response(req, |session| async move {
            crate::cross_signing_status_for_session(&session).await
        }),
        // --- key backup / recovery (issue #240) ---
        "recovery.enable" => block_on_task_response(req, |session| async move {
            crate::enable_recovery_for_session(&session).await
        }),
        "recovery.status" => block_on_task_response(req, |session| async move {
            crate::recovery_status_for_session(&session).await
        }),
        "recovery.recover" => match parse_params::<crate::RecoverParams>(req) {
            Ok(params) => block_on_task_response(req, |session| async move {
                crate::recover_for_session(&session, &params).await
            }),
            Err(response) => *response,
        },
        "task.watch" | "workspace.watch" => Response::error(
            req.id.clone(),
            METHOD_NOT_FOUND,
            "this method requires a streaming IPC connection",
        ),
        m if m == crate::METHOD_DEVICE_VERIFY_START => Response::error(
            req.id.clone(),
            METHOD_NOT_FOUND,
            "this method requires a streaming IPC connection",
        ),
        other => Response::error(
            req.id.clone(),
            METHOD_NOT_FOUND,
            format!("unknown method: {other}"),
        ),
    }
}

/// Run an `exec.start` loopback request on a dedicated async runtime.
///
/// The loopback needs no Matrix session (it runs the command on the local
/// host), so — unlike the task methods — this does not load the daemon session.
fn dispatch_call_start(req: &Request, params: &crate::CallStartParams) -> Response {
    let live = params.room.is_some() && params.agent.is_some();
    let result = if live {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(e) => {
                return Response::error(
                    req.id.clone(),
                    INTERNAL_ERROR,
                    format!("could not start async runtime: {e}"),
                )
            }
        };
        runtime.block_on(crate::start_call_matrix(params))
    } else {
        crate::start_call_loopback(params)
    };
    match serde_json::to_value(&result) {
        Ok(value) => Response::result(req.id.clone(), value),
        Err(e) => Response::error(req.id.clone(), INTERNAL_ERROR, e.to_string()),
    }
}

fn dispatch_exec_control_result(req: &Request, result: crate::ExecControlResult) -> Response {
    match serde_json::to_value(&result) {
        Ok(value) => Response::result(req.id.clone(), value),
        Err(e) => Response::error(req.id.clone(), INTERNAL_ERROR, e.to_string()),
    }
}

fn control_runtime(_req: &Request) -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start async runtime: {e}"))
}

fn dispatch_exec_stdin(req: &Request, params: &crate::ExecStdinParams) -> Response {
    if params.room.is_none() {
        // Loopback batch exec is synchronous (one IPC request runs to
        // completion), so there is no live stdin pipe to address. Reject the
        // no-`--room` case honestly instead of returning a permanently-dead
        // `accepted: false` result (issue #307).
        return Response::error(
            req.id.clone(),
            INVALID_PARAMS,
            crate::LOOPBACK_CONTROL_UNSUPPORTED.to_string(),
        );
    }
    let runtime = match control_runtime(req) {
        Ok(runtime) => runtime,
        Err(message) => return Response::error(req.id.clone(), INTERNAL_ERROR, message),
    };
    dispatch_exec_control_result(req, runtime.block_on(crate::send_exec_stdin_matrix(params)))
}

fn dispatch_exec_cancel(req: &Request, params: &crate::ExecCancelParams) -> Response {
    if params.room.is_none() {
        // Loopback batch exec has no live process handle to cancel; a runaway
        // command is bounded by the default timeout instead. Reject the
        // no-`--room` case honestly (issue #307).
        return Response::error(
            req.id.clone(),
            INVALID_PARAMS,
            crate::LOOPBACK_CONTROL_UNSUPPORTED.to_string(),
        );
    }
    let runtime = match control_runtime(req) {
        Ok(runtime) => runtime,
        Err(message) => return Response::error(req.id.clone(), INTERNAL_ERROR, message),
    };
    dispatch_exec_control_result(
        req,
        runtime.block_on(crate::send_exec_cancel_matrix(params)),
    )
}

fn dispatch_exec_start(
    req: &Request,
    params: &crate::ExecStartParams,
    exec_subscribers: Option<&crate::ExecSubscriberRegistry>,
) -> Response {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            return Response::error(
                req.id.clone(),
                INTERNAL_ERROR,
                format!("could not start async runtime: {e}"),
            )
        }
    };
    let live = params.room.is_some() && params.agent.is_some();
    let result = if live {
        match exec_subscribers {
            Some(registry) => runtime.block_on(crate::start_exec_matrix(params, registry)),
            None => crate::ExecStartResult {
                invocation_id: String::new(),
                request_id: String::new(),
                outcome: crate::ExecOutcome::Error {
                    kind: crate::ExecErrorKind::Remote,
                    message: "remote exec requires daemon subscriber registry".to_string(),
                },
            },
        }
    } else {
        runtime.block_on(crate::start_exec_loopback(params))
    };
    match serde_json::to_value(&result) {
        Ok(value) => Response::result(req.id.clone(), value),
        Err(e) => Response::error(req.id.clone(), INTERNAL_ERROR, e.to_string()),
    }
}

fn dispatch_task_watch(
    req: &Request,
    stream: &mut std::os::unix::net::UnixStream,
) -> io::Result<()> {
    let options = match parse_params::<crate::ListTasksOptions>(req) {
        Ok(options) => options,
        Err(response) => return write_ipc_response(stream, &response),
    };
    let session = match load_daemon_session_response(req) {
        Ok(session) => session,
        Err(response) => return write_ipc_response(stream, &response),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            return write_ipc_response(
                stream,
                &Response::error(
                    req.id.clone(),
                    INTERNAL_ERROR,
                    format!("could not start async runtime: {e}"),
                ),
            )
        }
    };

    let running = Arc::new(AtomicBool::new(true));
    let write_failed = Arc::new(AtomicBool::new(false));
    let stream_cell = std::cell::RefCell::new(stream);
    let request_id = req.id.clone();
    let running_for_callback = running.clone();
    let write_failed_for_callback = write_failed.clone();
    let callback = |update: crate::WatchUpdate<'_, Vec<mx_agent_protocol::schema::TaskState>>| {
        let payload: Value = match update {
            crate::WatchUpdate::Initial(tasks) => json!({ "event": "initial", "tasks": tasks }),
            crate::WatchUpdate::Changed { previous, current } => json!({
                "event": "changed",
                "previous": previous,
                "current": current,
                "changes": crate::diff_tasks(previous, current),
            }),
            crate::WatchUpdate::Reconnecting { attempt, error } => json!({
                "event": "reconnecting",
                "attempt": attempt,
                "error": error,
            }),
            crate::WatchUpdate::Reconnected => json!({ "event": "reconnected" }),
        };
        let response = Response::result(request_id.clone(), payload);
        if write_ipc_response(&mut stream_cell.borrow_mut(), &response).is_err() {
            write_failed_for_callback.store(true, Ordering::SeqCst);
            running_for_callback.store(false, Ordering::SeqCst);
        }
    };

    let result = runtime.block_on(crate::watch_tasks_for_session(
        &session,
        &options,
        crate::WatchConfig::default(),
        &running,
        callback,
    ));
    if write_failed.load(Ordering::SeqCst) {
        return Ok(());
    }
    match result {
        Ok(()) => Ok(()),
        Err(e) => write_ipc_response(
            &mut stream_cell.borrow_mut(),
            &Response::error(req.id.clone(), INTERNAL_ERROR, e.to_string()),
        ),
    }
}

/// Stream `workspace.watch` updates to the CLI over the open IPC connection
/// (issue #201), mirroring [`dispatch_task_watch`]. The daemon owns the Matrix
/// session; the CLI never restores it.
fn dispatch_workspace_watch(
    req: &Request,
    stream: &mut std::os::unix::net::UnixStream,
) -> io::Result<()> {
    let params = match parse_params::<crate::RoomParams>(req) {
        Ok(params) => params,
        Err(response) => return write_ipc_response(stream, &response),
    };
    let session = match load_daemon_session_response(req) {
        Ok(session) => session,
        Err(response) => return write_ipc_response(stream, &response),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            return write_ipc_response(
                stream,
                &Response::error(
                    req.id.clone(),
                    INTERNAL_ERROR,
                    format!("could not start async runtime: {e}"),
                ),
            )
        }
    };

    let running = Arc::new(AtomicBool::new(true));
    let write_failed = Arc::new(AtomicBool::new(false));
    let stream_cell = std::cell::RefCell::new(stream);
    let request_id = req.id.clone();
    let running_for_callback = running.clone();
    let write_failed_for_callback = write_failed.clone();
    let callback = |update: crate::WatchUpdate<'_, crate::WorkspaceStatus>| {
        let payload: Value = match update {
            crate::WatchUpdate::Initial(status) => json!({ "event": "initial", "status": status }),
            crate::WatchUpdate::Changed { previous, current } => json!({
                "event": "changed",
                "previous": previous,
                "current": current,
            }),
            crate::WatchUpdate::Reconnecting { attempt, error } => json!({
                "event": "reconnecting",
                "attempt": attempt,
                "error": error,
            }),
            crate::WatchUpdate::Reconnected => json!({ "event": "reconnected" }),
        };
        let response = Response::result(request_id.clone(), payload);
        if write_ipc_response(&mut stream_cell.borrow_mut(), &response).is_err() {
            write_failed_for_callback.store(true, Ordering::SeqCst);
            running_for_callback.store(false, Ordering::SeqCst);
        }
    };

    let result = runtime.block_on(crate::watch_workspace_status_for_session(
        &session,
        &params.room,
        crate::WatchConfig::default(),
        &running,
        callback,
    ));
    if write_failed.load(Ordering::SeqCst) {
        return Ok(());
    }
    match result {
        Ok(()) => Ok(()),
        Err(e) => write_ipc_response(
            &mut stream_cell.borrow_mut(),
            &Response::error(req.id.clone(), INTERNAL_ERROR, e.to_string()),
        ),
    }
}

/// Stream an interactive PTY `exec` session over the open IPC connection
/// (issue #238). The daemon owns the pseudo-terminal (loopback) or bridges the
/// session to a remote agent over the signed Matrix transport when `room`/`agent`
/// are set; the CLI never spawns the process itself.
fn dispatch_exec_pty(
    req: &Request,
    stream: &mut std::os::unix::net::UnixStream,
    exec_subscribers: &crate::ExecSubscriberRegistry,
) -> io::Result<()> {
    let params = match parse_params::<crate::ExecPtyParams>(req) {
        Ok(params) => params,
        Err(response) => return write_ipc_response(stream, &response),
    };
    let request_id = req.id.clone();
    if params.room.is_some() && params.agent.is_some() {
        crate::pty_ipc::run_pty_remote(&params, stream, &request_id, exec_subscribers)
    } else {
        crate::run_pty_loopback(&params, stream, &request_id)
    }
}

/// Stream an interactive device verification (`device.verify.start`) over the
/// open IPC connection (issue #240), mirroring [`dispatch_task_watch`]. The
/// daemon owns the verification flow; the CLI receives only flow frames
/// (`started` → `emoji-ready` → `confirmed`/`cancelled`) and never key material.
fn dispatch_device_verify(
    req: &Request,
    stream: &mut std::os::unix::net::UnixStream,
) -> io::Result<()> {
    let params = match parse_params::<crate::DeviceVerifyStartParams>(req) {
        Ok(params) => params,
        Err(response) => return write_ipc_response(stream, &response),
    };
    let session = match load_daemon_session_response(req) {
        Ok(session) => session,
        Err(response) => return write_ipc_response(stream, &response),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            return write_ipc_response(
                stream,
                &Response::error(
                    req.id.clone(),
                    INTERNAL_ERROR,
                    format!("could not start async runtime: {e}"),
                ),
            )
        }
    };

    let running = Arc::new(AtomicBool::new(true));
    let write_failed = Arc::new(AtomicBool::new(false));
    let stream_cell = std::cell::RefCell::new(stream);
    let request_id = req.id.clone();
    let running_for_callback = running.clone();
    let write_failed_for_callback = write_failed.clone();
    let frame = |frame: crate::DeviceVerifyFrame| {
        let payload = serde_json::to_value(&frame).unwrap_or(Value::Null);
        let response = Response::result(request_id.clone(), payload);
        if write_ipc_response(&mut stream_cell.borrow_mut(), &response).is_err() {
            write_failed_for_callback.store(true, Ordering::SeqCst);
            running_for_callback.store(false, Ordering::SeqCst);
        }
    };
    // The operator's confirm/cancel arrives as a control frame on this same
    // connection. The wait is bounded by `VERIFY_DEADLINE`: a stalled operator or
    // hung client cannot park the dispatch thread forever. A `cancel` method,
    // EOF, any read error, or the deadline elapsing all fail safe to a cancel —
    // never an unintended confirm (issue #258). Classification lives entirely in
    // `read_verify_decision`.
    let wait_decision = || {
        let mut guard = stream_cell.borrow_mut();
        crate::read_verify_decision(&mut guard, crate::VERIFY_DEADLINE)
    };

    let result = runtime.block_on(crate::run_device_verify(
        &session,
        &params,
        &running,
        frame,
        wait_decision,
    ));
    if write_failed.load(Ordering::SeqCst) {
        return Ok(());
    }
    match result {
        Ok(()) => Ok(()),
        Err(e) => write_ipc_response(
            &mut stream_cell.borrow_mut(),
            &Response::error(req.id.clone(), INTERNAL_ERROR, e.to_string()),
        ),
    }
}

fn dispatch_streaming(
    req: &Request,
    stream: &mut std::os::unix::net::UnixStream,
    pid: u32,
    started_at: u64,
    socket_path: &str,
    supervisor: &WorkerSupervisor,
    exec_subscribers: &crate::ExecSubscriberRegistry,
) -> io::Result<()> {
    if req.method == "task.watch" {
        dispatch_task_watch(req, stream)
    } else if req.method == "workspace.watch" {
        dispatch_workspace_watch(req, stream)
    } else if req.method == crate::METHOD_EXEC_PTY {
        dispatch_exec_pty(req, stream, exec_subscribers)
    } else if req.method == crate::METHOD_DEVICE_VERIFY_START {
        dispatch_device_verify(req, stream)
    } else {
        let response = dispatch(
            req,
            pid,
            started_at,
            socket_path,
            supervisor,
            Some(exec_subscribers),
        );
        write_ipc_response(stream, &response)
    }
}

/// Open (creating if needed) the background daemon log with owner-only `0600`
/// permissions, regardless of the process umask.
///
/// `daemon.log` captures the foreground daemon's stdout and stderr — including
/// everything it logs — so it is held to the same private-file posture as the
/// rest of the daemon's local state (`session.json`, the status file, the audit
/// log). The file is created with mode `0o600` atomically via
/// [`OpenOptionsExt::mode`] — no world-readable window between create and
/// `chmod` — and its permissions are re-asserted so a pre-existing log left
/// loose by an earlier build or an operator mistake is tightened back to
/// `0600`. Mirrors [`crate::AuditLog`]'s append path.
///
/// [`OpenOptionsExt::mode`]: std::os::unix::fs::OpenOptionsExt::mode
fn open_log_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Spawn the daemon as a detached background process and wait for it to report
/// readiness via the status file.
pub fn start_background() -> io::Result<RunningStatus> {
    let paths = Paths::resolve();
    paths.ensure_runtime_dir()?;

    // Fail fast (before spawning) if the runtime directory is unsafe.
    mx_agent_ipc::ensure_safe_parent_dir(&paths.runtime_dir)?;

    // Refuse before spawning on a present-but-unusable policy, so the operator
    // gets the precise diagnostic immediately instead of the generic 5s
    // readiness timeout (issue #350). The `run_foreground` gate remains the
    // authoritative check; this is a UX nicety for a precise immediate error.
    if let crate::policy::PolicyResolution::Malformed { path, display } =
        crate::policy::resolve_policy()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed policy {}: {display}", path.display()),
        ));
    }

    let exe = std::env::current_exe()?;
    let log = open_log_file(&paths.log_file)?;
    let log_err = log.try_clone()?;

    Command::new(exe)
        .args(["daemon", "start", "--foreground"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()?;

    // Poll for the child to write its status file.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(running) = status()? {
            return Ok(running);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "daemon did not become ready within timeout",
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Stop the running daemon: `SIGTERM`, then `SIGKILL` after `grace`.
pub fn stop(grace: Duration) -> io::Result<StopOutcome> {
    let paths = Paths::resolve();
    let Some(sf) = read_status_file(&paths)? else {
        return Ok(StopOutcome::NotRunning);
    };
    let pid = sf.pid;
    if !is_alive(pid) {
        remove_status_file(&paths);
        return Ok(StopOutcome::NotRunning);
    }

    let target = Pid::from_raw(pid as i32);
    let _ = kill(target, Signal::SIGTERM);

    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if !is_alive(pid) {
            remove_status_file(&paths);
            return Ok(StopOutcome::Stopped(pid));
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = kill(target, Signal::SIGKILL);
    std::thread::sleep(Duration::from_millis(100));
    // The force-killed daemon never ran its graceful exec-child teardown, so
    // SIGKILL any process groups it recorded in the live-pgid sidecar; otherwise
    // in-flight exec children (and their grandchildren) would orphan (issue #316).
    crate::exec::kill_persisted_live_exec_children(&SessionPaths::resolve());
    remove_status_file(&paths);
    Ok(StopOutcome::Killed(pid))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// An idle supervisor for dispatch tests: it spawns no workers (its
    /// `ensure_started` is never called here), so `health()` is `None` and
    /// `daemon.status` reports no sync loop — exactly the pre-login state these
    /// tests exercise.
    fn test_supervisor() -> WorkerSupervisor {
        WorkerSupervisor::new(crate::ExecSubscriberRegistry::new())
    }

    struct TempRuntime {
        dir: PathBuf,
        _guard: MutexGuard<'static, ()>,
    }

    impl TempRuntime {
        fn new(tag: &str) -> Self {
            let guard = env_lock();
            let dir = std::env::temp_dir().join(format!(
                "mx-agent-test-{}-{}-{}",
                tag,
                std::process::id(),
                now_unix()
            ));
            std::env::set_var(ENV_RUNTIME_DIR, &dir);
            std::env::set_var(crate::session::ENV_DATA_DIR, dir.join("data"));
            Self { dir, _guard: guard }
        }
    }

    impl Drop for TempRuntime {
        fn drop(&mut self) {
            std::env::remove_var(ENV_RUNTIME_DIR);
            std::env::remove_var(crate::session::ENV_DATA_DIR);
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn status_is_none_when_no_status_file() {
        let _rt = TempRuntime::new("none");
        assert!(status().unwrap().is_none());
    }

    #[test]
    fn stale_status_file_is_cleaned_up() {
        let _rt = TempRuntime::new("stale");
        let paths = Paths::resolve();
        // PID 0x7FFFFFFE is extremely unlikely to be alive.
        let sf = StatusFile {
            pid: 0x7FFF_FFFE,
            started_at_unix: now_unix(),
            socket_path: paths.socket_path.to_string_lossy().into_owned(),
            version: DAEMON_VERSION.to_string(),
        };
        write_status_file(&paths, &sf).unwrap();
        assert!(paths.status_file.exists());
        assert!(status().unwrap().is_none());
        assert!(!paths.status_file.exists(), "stale file should be removed");
    }

    #[test]
    fn status_reports_self_as_running() {
        let _rt = TempRuntime::new("selfpid");
        let paths = Paths::resolve();
        let sf = StatusFile {
            pid: std::process::id(),
            started_at_unix: now_unix().saturating_sub(2),
            socket_path: paths.socket_path.to_string_lossy().into_owned(),
            version: DAEMON_VERSION.to_string(),
        };
        write_status_file(&paths, &sf).unwrap();
        let running = status().unwrap().expect("should be running");
        assert_eq!(running.pid, std::process::id());
        assert!(running.uptime_seconds >= 2);
        assert_eq!(running.version, DAEMON_VERSION);
        assert!(running.to_json().contains("\"running\":true"));
    }

    #[test]
    fn task_ipc_methods_validate_params_before_loading_session() {
        for method in [
            "task.create",
            "task.update",
            "task.list",
            "task.graph",
            "task.cancel",
        ] {
            let req = Request::new(json!(1), method, Value::Null);
            let response = dispatch(
                &req,
                1,
                now_unix(),
                "/tmp/daemon.sock",
                &test_supervisor(),
                None,
            );
            let error = response.error.expect("invalid params should be rejected");
            assert_eq!(error.code, INVALID_PARAMS);
            assert!(error.message.contains("invalid params"));
            assert!(error.message.contains(method));
        }
    }

    #[test]
    fn task_ipc_methods_report_missing_daemon_session() {
        let _rt = TempRuntime::new("task-session");
        let req = Request::new(
            json!(1),
            "task.list",
            json!({"room":"!abc:matrix.org","state":null,"assigned_to":null}),
        );
        let response = dispatch(
            &req,
            1,
            now_unix(),
            "/tmp/daemon.sock",
            &test_supervisor(),
            None,
        );
        let error = response.error.expect("missing session should be rejected");
        assert_eq!(error.code, INTERNAL_ERROR);
        assert!(error.message.contains("not logged in"));
    }

    /// Every daemon-mediated Matrix command added in issue #201 must validate
    /// its params before loading the session, so malformed input is a clean
    /// `INVALID_PARAMS` error rather than a panic or a session read.
    #[test]
    fn matrix_ipc_methods_validate_params_before_loading_session() {
        let methods = [
            "workspace.create",
            "workspace.join",
            "workspace.attach",
            "workspace.grant",
            "workspace.status",
            "agent.register",
            "agent.list",
            "agent.show",
            "agent.tools",
            "trust.publish",
            "trust.state",
            "approval.decide",
            "share.file",
            "share.diff",
            "share.env",
            "share.list",
            "share.get",
            "invocation.list",
            "invocation.get",
            "invocation.cancel",
            "invocation.artifact",
        ];
        for method in methods {
            // `null` params never satisfy a struct-shaped parameter.
            let req = Request::new(json!(1), method, Value::Null);
            let response = dispatch(
                &req,
                1,
                now_unix(),
                "/tmp/daemon.sock",
                &test_supervisor(),
                None,
            );
            let error = response
                .error
                .unwrap_or_else(|| panic!("{method}: invalid params should be rejected"));
            assert_eq!(error.code, INVALID_PARAMS, "{method}");
            assert!(error.message.contains("invalid params"), "{method}");
            assert!(error.message.contains(method), "{method}");
        }
    }

    /// A valid Matrix-backed request with no stored daemon session is reported
    /// as "not logged in" rather than attempting a Matrix operation.
    #[test]
    fn matrix_ipc_methods_report_missing_daemon_session() {
        let _rt = TempRuntime::new("matrix-session");
        let req = Request::new(
            json!(1),
            "workspace.status",
            json!({"room":"!abc:matrix.org"}),
        );
        let response = dispatch(
            &req,
            1,
            now_unix(),
            "/tmp/daemon.sock",
            &test_supervisor(),
            None,
        );
        let error = response.error.expect("missing session should be rejected");
        assert_eq!(error.code, INTERNAL_ERROR);
        assert!(error.message.contains("not logged in"));
    }

    /// The streaming methods are rejected on the single-response path so a
    /// non-streaming caller gets a clear error instead of a hang.
    #[test]
    fn streaming_methods_require_streaming_connection() {
        for method in [
            "task.watch",
            "workspace.watch",
            crate::METHOD_DEVICE_VERIFY_START,
        ] {
            let req = Request::new(json!(1), method, json!({"room":"!abc:matrix.org"}));
            let response = dispatch(
                &req,
                1,
                now_unix(),
                "/tmp/daemon.sock",
                &test_supervisor(),
                None,
            );
            let error = response
                .error
                .expect("streaming method on single-response path");
            assert_eq!(error.code, METHOD_NOT_FOUND, "{method}");
            assert!(
                error.message.contains("streaming"),
                "{method}: expected streaming-connection message; got: {}",
                error.message,
            );
        }
    }

    /// The interactive SAS decision is delivered in-band on the held-open
    /// `device.verify.start` connection (issue #259), so the formerly-registered
    /// out-of-band `device.verify.confirm` / `.cancel` methods are gone and now
    /// fall through to the unknown-method arm.
    #[test]
    fn removed_device_verify_confirm_cancel_methods_are_unknown() {
        for method in ["device.verify.confirm", "device.verify.cancel"] {
            let req = Request::new(json!(1), method, json!({"flow_id":"flow_abc"}));
            let response = dispatch(
                &req,
                1,
                now_unix(),
                "/tmp/daemon.sock",
                &test_supervisor(),
                None,
            );
            let error = response
                .error
                .unwrap_or_else(|| panic!("{method}: removed method should error"));
            assert_eq!(error.code, METHOD_NOT_FOUND, "{method}");
            assert!(error.message.contains("unknown method"), "{method}");
            assert!(error.message.contains(method), "{method}");
        }
    }

    #[test]
    fn exec_start_rejects_invalid_params() {
        // Missing the required `command` field.
        let req = Request::new(json!(1), "exec.start", json!({"cwd":"/tmp"}));
        let response = dispatch(
            &req,
            1,
            now_unix(),
            "/tmp/daemon.sock",
            &test_supervisor(),
            None,
        );
        let error = response.error.expect("invalid params should be rejected");
        assert_eq!(error.code, INVALID_PARAMS);
        assert!(error.message.contains("exec.start"));
    }

    #[test]
    fn exec_start_runs_loopback_through_dispatch() {
        // A valid request runs the command in the daemon and returns frames
        // with the exit code — no Matrix session required.
        let req = Request::new(
            json!(1),
            "exec.start",
            json!({"command":["true"],"cwd":std::env::temp_dir()}),
        );
        let response = dispatch(
            &req,
            1,
            now_unix(),
            "/tmp/daemon.sock",
            &test_supervisor(),
            None,
        );
        assert!(response.error.is_none(), "unexpected error: {response:?}");
        let result = response.result.expect("exec.start should return a result");
        let parsed: crate::ExecStartResult = serde_json::from_value(result).unwrap();
        match parsed.outcome {
            crate::ExecOutcome::Ok { frames } => {
                assert!(matches!(
                    frames.last(),
                    Some(crate::ExecFrame::Finished(f)) if f.exit_code == Some(0)
                ));
            }
            other => panic!("expected Ok outcome, got {other:?}"),
        }
    }

    #[test]
    fn exec_control_methods_reject_loopback_without_room() {
        // Synchronous loopback exec has no live stdin pipe or process handle, so
        // exec.stdin/exec.cancel without a `--room` target are rejected with a
        // JSON-RPC error rather than a permanently-dead `accepted: false` result
        // (issue #307).
        let stdin_req = Request::new(
            json!(1),
            "exec.stdin",
            json!({"invocation_id":"inv_1","data":[104,105],"eof":true}),
        );
        let stdin_response = dispatch(
            &stdin_req,
            1,
            now_unix(),
            "/tmp/daemon.sock",
            &test_supervisor(),
            None,
        );
        assert!(stdin_response.result.is_none());
        let error = stdin_response
            .error
            .expect("stdin without room is an error");
        assert_eq!(error.code, INVALID_PARAMS);
        assert!(error.message.contains("loopback exec is synchronous"));

        let cancel_req = Request::new(
            json!(2),
            "exec.cancel",
            json!({"invocation_id":"inv_1","reason":"test"}),
        );
        let cancel_response = dispatch(
            &cancel_req,
            1,
            now_unix(),
            "/tmp/daemon.sock",
            &test_supervisor(),
            None,
        );
        assert!(cancel_response.result.is_none());
        let error = cancel_response
            .error
            .expect("cancel without room is an error");
        assert_eq!(error.code, INVALID_PARAMS);
        assert!(error.message.contains("loopback exec is synchronous"));
    }

    #[test]
    fn stop_when_not_running_is_idempotent() {
        let _rt = TempRuntime::new("stop");
        assert_eq!(
            stop(Duration::from_millis(200)).unwrap(),
            StopOutcome::NotRunning
        );
    }

    #[test]
    fn open_log_file_creates_private_mode() {
        // Issue #311: `daemon.log` captures the daemon's stdout/stderr and must
        // be owner-only regardless of the umask, like the status and audit logs.
        let base =
            std::env::temp_dir().join(format!("mx-log-mode-{}-{}", std::process::id(), now_unix()));
        fs::create_dir_all(&base).expect("mk base");
        let path = base.join("daemon.log");

        let file = open_log_file(&path).expect("open log");
        drop(file);

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "daemon.log must be created 0600");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn open_log_file_tightens_preexisting_loose_log() {
        // A log left world-readable by an earlier build is re-tightened to 0600
        // on the next open, not left exposed.
        let base = std::env::temp_dir().join(format!(
            "mx-log-tighten-{}-{}",
            std::process::id(),
            now_unix()
        ));
        fs::create_dir_all(&base).expect("mk base");
        let path = base.join("daemon.log");
        fs::write(&path, b"old line\n").expect("seed log");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen");

        let file = open_log_file(&path).expect("open log");
        drop(file);

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "pre-existing loose log must be tightened to 0600"
        );
        // Append mode must preserve the existing contents.
        let contents = fs::read_to_string(&path).unwrap();
        assert!(
            contents.starts_with("old line"),
            "log must be append, not truncate"
        );

        let _ = fs::remove_dir_all(&base);
    }

    // ── Policy-aware lifecycle tests (issue #350) ─────────────────────────────
    //
    // Tests that set MX_AGENT_CONFIG_DIR hold the crate-level
    // `crate::tests::config_dir_env_lock` AFTER the module-local `env_lock` (via
    // TempRuntime), so they are serialized against each other and against the
    // `policy` and `scheduler_loop` module tests. TempRuntime always takes
    // env_lock first; acquiring config_dir_env_lock second is consistent and
    // deadlock-free.

    /// RAII guard that points MX_AGENT_CONFIG_DIR at a temp dir and cleans up.
    struct PolicySetup {
        config_dir: std::path::PathBuf,
        _config_lock: std::sync::MutexGuard<'static, ()>,
    }

    impl PolicySetup {
        fn new_malformed(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static CTR: AtomicU64 = AtomicU64::new(0);
            let n = CTR.fetch_add(1, Ordering::Relaxed);
            let lock = crate::tests::config_dir_env_lock();
            let dir = std::env::temp_dir().join(format!(
                "mx-agent-lc-policy-{}-{}-{}",
                tag,
                std::process::id(),
                n
            ));
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("policy.toml"), "not valid toml !! [[[").unwrap();
            std::env::set_var(mx_agent_policy::ENV_CONFIG_DIR, &dir);
            Self {
                config_dir: dir,
                _config_lock: lock,
            }
        }

        fn new_absent(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static CTR: AtomicU64 = AtomicU64::new(0);
            let n = CTR.fetch_add(1, Ordering::Relaxed);
            let lock = crate::tests::config_dir_env_lock();
            let dir = std::env::temp_dir().join(format!(
                "mx-agent-lc-policy-absent-{}-{}-{}",
                tag,
                std::process::id(),
                n
            ));
            // Dir does not exist → policy.toml cannot exist → Absent.
            std::env::set_var(mx_agent_policy::ENV_CONFIG_DIR, &dir);
            Self {
                config_dir: dir,
                _config_lock: lock,
            }
        }
    }

    impl Drop for PolicySetup {
        fn drop(&mut self) {
            std::env::remove_var(mx_agent_policy::ENV_CONFIG_DIR);
            let _ = fs::remove_dir_all(&self.config_dir);
        }
    }

    /// `run_foreground` must refuse to start (Err(InvalidData)) when the policy
    /// file is present but unparseable. The gate fires before socket binding so
    /// the function returns without side effects (issue #350).
    #[test]
    fn run_foreground_refuses_malformed_policy() {
        let _rt = TempRuntime::new("fg-malformed");
        let _policy = PolicySetup::new_malformed("fg");
        let err = run_foreground().expect_err("run_foreground must refuse a malformed policy");
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidData,
            "must be InvalidData, got {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("malformed policy"),
            "error must name the malformed state: {msg}"
        );
    }

    // No separate test for run_foreground on absent policy: the full event loop
    // is impractical in a unit test. The absent-policy path is covered by the
    // daemon.status dispatch tests below, which use resolve_policy() directly.

    /// The `daemon.status` IPC handler must populate `RunningStatus.policy` with
    /// a `PolicyStatus` when the policy file is present but malformed. This is
    /// the persistent runtime warning surface (issue #350).
    #[test]
    fn daemon_status_dispatch_policy_populated_when_malformed() {
        let _rt = TempRuntime::new("status-malformed-policy");
        let _policy = PolicySetup::new_malformed("dispatch");
        let req = Request::new(serde_json::json!(1), "daemon.status", serde_json::json!({}));
        let response = dispatch(
            &req,
            1,
            now_unix(),
            "/tmp/daemon.sock",
            &test_supervisor(),
            None,
        );
        let result = response
            .result
            .expect("daemon.status must succeed even when policy is malformed");
        let running: RunningStatus = serde_json::from_value(result).unwrap();
        let policy_status = running
            .policy
            .expect("daemon.status must include policy field when malformed");
        assert_eq!(
            policy_status.state,
            crate::policy::POLICY_STATE_MALFORMED,
            "state must be the canonical malformed string"
        );
        assert!(!policy_status.path.is_empty(), "path must be set");
        assert!(
            !policy_status.error.is_empty(),
            "error must carry the diagnostic"
        );
    }

    /// The `daemon.status` IPC handler must omit `RunningStatus.policy` when the
    /// policy file is absent (deny-all default). The JSON output must not contain
    /// the `policy` key so that older consumers remain unaffected (issue #350).
    #[test]
    fn daemon_status_dispatch_policy_absent_when_no_policy() {
        let _rt = TempRuntime::new("status-absent-policy");
        let _policy = PolicySetup::new_absent("dispatch-absent");
        let req = Request::new(serde_json::json!(1), "daemon.status", serde_json::json!({}));
        let response = dispatch(
            &req,
            1,
            now_unix(),
            "/tmp/daemon.sock",
            &test_supervisor(),
            None,
        );
        let result = response
            .result
            .expect("daemon.status must succeed when policy is absent");
        let running: RunningStatus = serde_json::from_value(result).unwrap();
        assert!(
            running.policy.is_none(),
            "daemon.status must omit policy when absent"
        );
        let json = running.to_json();
        assert!(
            !json.contains("\"policy\""),
            "JSON must not contain policy key when absent: {json}"
        );
    }

    /// `RunningStatus::to_json()` must include the `policy` object when it is
    /// `Some`, so `--json` consumers can detect and surface a malformed policy
    /// programmatically (issue #350).
    #[test]
    fn running_status_to_json_includes_policy_when_set() {
        let status = RunningStatus {
            running: true,
            pid: 1234,
            uptime_seconds: 60,
            socket_path: "/tmp/daemon.sock".to_string(),
            version: DAEMON_VERSION.to_string(),
            sync: None,
            policy: Some(crate::policy::PolicyStatus {
                state: crate::policy::POLICY_STATE_MALFORMED.to_string(),
                path: "/home/user/.config/mx-agent/policy.toml".to_string(),
                error: "failed to parse policy: expected key at line 1 col 1".to_string(),
            }),
        };
        let json = status.to_json();
        assert!(
            json.contains("\"policy\""),
            "JSON must include policy key: {json}"
        );
        assert!(
            json.contains(crate::policy::POLICY_STATE_MALFORMED),
            "JSON must include the state value: {json}"
        );
        assert!(
            json.contains("policy.toml"),
            "JSON must include the file path: {json}"
        );
    }

    /// `RunningStatus::to_json()` must NOT include the `policy` key when it is
    /// `None`, keeping the status payload backward-compatible for healthy daemons
    /// and older CLI consumers (issue #350).
    #[test]
    fn running_status_to_json_omits_policy_when_none() {
        let status = RunningStatus {
            running: true,
            pid: 1234,
            uptime_seconds: 60,
            socket_path: "/tmp/daemon.sock".to_string(),
            version: DAEMON_VERSION.to_string(),
            sync: None,
            policy: None,
        };
        let json = status.to_json();
        assert!(
            !json.contains("\"policy\""),
            "JSON must not contain policy key when None: {json}"
        );
    }

    // ── #371: request/response handler homeserver-read timeout ────────────────

    #[test]
    fn request_budget_uses_recovery_ceiling_only_for_recovery_methods() {
        assert_eq!(request_budget("recovery.enable"), IPC_RECOVERY_BUDGET);
        assert_eq!(request_budget("recovery.recover"), IPC_RECOVERY_BUDGET);
        for method in ["task.graph", "agent.list", "approval.decide", "share.get"] {
            assert_eq!(request_budget(method), IPC_REQUEST_BUDGET);
        }
        // `recovery.status` is a light read, so it keeps the default ceiling.
        assert_eq!(request_budget("recovery.status"), IPC_REQUEST_BUDGET);
        // The recovery ceiling must be the larger of the two.
        assert!(IPC_RECOVERY_BUDGET > IPC_REQUEST_BUDGET);
    }

    #[tokio::test]
    async fn run_bounded_abandons_a_stalled_future() {
        // A handler future that never completes must be abandoned at the budget,
        // not awaited forever (issue #371).
        let outcome = run_bounded::<()>(Duration::from_millis(20), async {
            std::future::pending::<()>().await;
            Ok(())
        })
        .await;
        assert!(matches!(outcome, BoundedOutcome::TimedOut));
    }

    #[tokio::test]
    async fn run_bounded_passes_a_ready_future_through() {
        let outcome = run_bounded(Duration::from_secs(5), async { Ok(7_i32) }).await;
        match outcome {
            BoundedOutcome::Completed(Ok(value)) => assert_eq!(value, 7),
            _ => panic!("a ready future must complete within budget"),
        }
    }

    #[tokio::test]
    async fn run_bounded_propagates_a_handler_error() {
        let outcome = run_bounded::<()>(Duration::from_secs(5), async {
            Err(crate::WorkspaceError::Io(io::Error::other("boom")))
        })
        .await;
        match outcome {
            BoundedOutcome::Completed(Err(e)) => assert!(e.to_string().contains("boom")),
            _ => panic!("a handler error must be propagated, not swallowed"),
        }
    }

    #[test]
    fn bounded_response_maps_timeout_to_error_naming_method_and_budget() {
        let req = Request::new(json!(1), "task.graph", Value::Null);
        let response =
            bounded_response::<()>(&req, Duration::from_secs(60), BoundedOutcome::TimedOut);
        let error = response.error.expect("a timeout must be an error response");
        assert_eq!(error.code, INTERNAL_ERROR);
        assert!(
            error.message.contains("timed out"),
            "message must say it timed out: {}",
            error.message
        );
        assert!(
            error.message.contains("60s"),
            "message must name the budget: {}",
            error.message
        );
        assert!(
            error.message.contains("task.graph"),
            "message must name the method: {}",
            error.message
        );
    }

    #[test]
    fn bounded_response_maps_completed_ok_to_result() {
        let req = Request::new(json!(2), "task.graph", Value::Null);
        let response = bounded_response(
            &req,
            IPC_REQUEST_BUDGET,
            BoundedOutcome::Completed(Ok(json!({"ok": true}))),
        );
        assert!(!response.is_error());
        assert_eq!(response.result, Some(json!({"ok": true})));
    }

    #[test]
    fn bounded_response_maps_completed_err_to_error() {
        let req = Request::new(json!(3), "task.graph", Value::Null);
        let outcome: BoundedOutcome<()> =
            BoundedOutcome::Completed(Err(crate::WorkspaceError::Io(io::Error::other("nope"))));
        let response = bounded_response(&req, IPC_REQUEST_BUDGET, outcome);
        let error = response
            .error
            .expect("a handler error must be an error response");
        assert_eq!(error.code, INTERNAL_ERROR);
        assert!(error.message.contains("nope"));
    }

    /// Real-socket regression (issue #371, acceptance #2): a request/response
    /// handler that stalls on a homeserver read returns a bounded timeout error
    /// over the socket, and the connection is NOT poisoned — a subsequent request
    /// on the same connection is still served (the #368/#258 failure class).
    #[test]
    fn stalled_handler_times_out_over_socket_without_poisoning_connection() {
        use mx_agent_ipc::{read_frame, serve_streaming, write_frame};
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::sync::atomic::{AtomicUsize, Ordering};

        static CTR: AtomicUsize = AtomicUsize::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let socket_path =
            std::env::temp_dir().join(format!("mx_ipc_371_{}_{}.sock", std::process::id(), n));
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).ok();
        }
        let listener = UnixListener::bind(&socket_path).unwrap();

        // Route a "stalls" method through the production timeout wrapper around a
        // never-completing future (a stand-in for a stalled homeserver read) with
        // a short test budget; "ping" returns immediately.
        std::thread::spawn(move || {
            serve_streaming(&listener, move |req, stream| {
                let response = match req.method.as_str() {
                    "stalls" => {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap();
                        let budget = Duration::from_millis(150);
                        let outcome = runtime.block_on(run_bounded::<()>(budget, async {
                            std::future::pending::<()>().await;
                            Ok(())
                        }));
                        bounded_response(req, budget, outcome)
                    }
                    "ping" => Response::result(req.id.clone(), json!({"pong": true})),
                    other => Response::error(
                        req.id.clone(),
                        METHOD_NOT_FOUND,
                        format!("unknown: {other}"),
                    ),
                };
                let bytes = serde_json::to_vec(&response).unwrap();
                write_frame(stream, &bytes)
            })
            .ok();
        });

        let mut conn = UnixStream::connect(&socket_path).unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        // Request 1: the stalled handler must return a bounded *error*, not hang.
        let req1 = Request::new(json!(1), "stalls", Value::Null);
        write_frame(&mut conn, &serde_json::to_vec(&req1).unwrap()).unwrap();
        let frame1 = read_frame(&mut conn)
            .expect("read error on the stalled request")
            .expect("a stalled handler must return a bounded response, not hang (issue #371)");
        let resp1: Response = serde_json::from_slice(&frame1).unwrap();
        assert!(
            resp1.is_error(),
            "the stalled handler must surface a timeout error"
        );
        let err1 = resp1.error.unwrap();
        assert_eq!(err1.code, INTERNAL_ERROR);
        assert!(
            err1.message.contains("timed out"),
            "message: {}",
            err1.message
        );

        // Request 2 on the SAME connection: the connection must not be poisoned.
        let req2 = Request::new(json!(2), "ping", Value::Null);
        write_frame(&mut conn, &serde_json::to_vec(&req2).unwrap()).unwrap();
        let frame2 = read_frame(&mut conn)
            .expect("read error on the follow-up request")
            .expect("the connection must stay usable after a bounded timeout (issue #368/#258)");
        let resp2: Response = serde_json::from_slice(&frame2).unwrap();
        assert!(!resp2.is_error(), "the follow-up request must succeed");
        assert_eq!(resp2.result, Some(json!({"pong": true})));

        std::fs::remove_file(&socket_path).ok();
    }
}
