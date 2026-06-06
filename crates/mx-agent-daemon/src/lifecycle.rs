//! Daemon process lifecycle: start (foreground/background), status, and stop.
//!
//! State is tracked with a small JSON status file under the runtime directory
//! (see `docs/architecture.md`, section 10). The Unix socket itself is created
//! in a later phase; this module only records its intended path.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
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
    }))
}

/// Run the daemon in the foreground until `SIGINT`/`SIGTERM`.
///
/// Writes the status file on startup and removes it on shutdown.
pub fn run_foreground() -> io::Result<()> {
    let paths = Paths::resolve();
    paths.ensure_runtime_dir()?;
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

    // Start the Matrix sync loop if a session is present. The loop's health is
    // shared with the IPC handler so `daemon.status` reports live progress. The
    // loop runs on its own Tokio runtime and is signalled to stop on shutdown.
    // When a session is present the same restored client also drives the live
    // task scheduler loop (architecture §9.2, issue #199).
    let sync_running = Arc::new(AtomicBool::new(true));
    let exec_subscribers = crate::ExecSubscriberRegistry::new();
    let (sync_thread, scheduler_thread, health) =
        spawn_matrix_workers(sync_running.clone(), exec_subscribers.clone());

    // Serve IPC requests on a background thread. The thread is torn down when
    // the process exits after shutdown.
    let listener = socket.listener().try_clone()?;
    let handler_socket = socket_path.clone();
    let handler_health = health.clone();
    let _server = std::thread::spawn(move || {
        let handler = move |req: &Request, stream: &mut std::os::unix::net::UnixStream| {
            dispatch_streaming(
                req,
                stream,
                pid,
                started_at,
                &handler_socket,
                &handler_health,
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

    // Signal the sync and scheduler loops to stop and wait for them to wind down.
    sync_running.store(false, Ordering::SeqCst);
    if let Some(handle) = sync_thread {
        let _ = handle.join();
    }
    if let Some(handle) = scheduler_thread {
        let _ = handle.join();
    }

    remove_status_file(&paths);
    drop(socket);
    tracing::info!(pid, "daemon stopped");
    Ok(())
}

/// Type alias for the pair of background worker threads (sync + scheduler).
type WorkerThreads = (
    Option<std::thread::JoinHandle<()>>,
    Option<std::thread::JoinHandle<()>>,
);

/// Spawn the Matrix sync loop and the live task scheduler loop, if a session is
/// stored, sharing one restored client between them.
///
/// Returns `(None, None, None)` (and does nothing) when no Matrix session exists
/// yet, so the daemon runs cleanly before login. The sync thread owns a
/// current-thread Tokio runtime that drives [`crate::sync::run_matrix_sync`];
/// the scheduler thread owns its own runtime and drives
/// [`crate::run_scheduler_loop`] over the same client, so only the sync loop
/// advances the session token while the scheduler reads task state and claims
/// runnable assigned tasks (architecture §9.2, issue #199).
fn spawn_matrix_workers(
    running: Arc<AtomicBool>,
    exec_subscribers: crate::ExecSubscriberRegistry,
) -> (
    Option<std::thread::JoinHandle<()>>,
    Option<std::thread::JoinHandle<()>>,
    SharedHealth,
) {
    let session_paths = SessionPaths::resolve();
    let session = match load_session(&session_paths) {
        Ok(Some(session)) => session,
        Ok(None) => {
            tracing::info!("no Matrix session stored; sync and scheduler loops not started");
            return (None, None, None);
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not load Matrix session; sync and scheduler loops not started");
            return (None, None, None);
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
    let publish_client = shared_client.clone();
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
    });

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
        crate::run_scheduler_loop(client, running, crate::DEFAULT_SCHEDULER_INTERVAL);
    });

    let threads: WorkerThreads = (Some(sync_handle), Some(scheduler_handle));
    (threads.0, threads.1, Some(health))
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
    match runtime.block_on(f(session)) {
        Ok(value) => match serde_json::to_value(value) {
            Ok(value) => Response::result(req.id.clone(), value),
            Err(e) => Response::error(req.id.clone(), INTERNAL_ERROR, e.to_string()),
        },
        Err(e) => Response::error(req.id.clone(), INTERNAL_ERROR, e.to_string()),
    }
}

/// Dispatch a single-response IPC request against the running daemon.
fn dispatch(
    req: &Request,
    pid: u32,
    started_at: u64,
    socket_path: &str,
    health: &SharedHealth,
    exec_subscribers: Option<&crate::ExecSubscriberRegistry>,
) -> Response {
    match req.method.as_str() {
        "daemon.ping" => Response::result(req.id.clone(), json!({"pong": true})),
        "daemon.status" => {
            let sync = health
                .as_ref()
                .map(|h| h.lock().unwrap_or_else(|e| e.into_inner()).clone());
            let status = RunningStatus {
                running: true,
                pid,
                uptime_seconds: now_unix().saturating_sub(started_at),
                socket_path: socket_path.to_string(),
                version: DAEMON_VERSION.to_string(),
                sync,
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
                // Best-effort agent snapshot for agent-dependent diagnostics;
                // when it cannot be read, agent checks are skipped rather than
                // failing the graph query.
                let agents = crate::list_agents_for_session(
                    &session,
                    &crate::ListAgentsOptions {
                        room: options.room.clone(),
                        capabilities: Vec::new(),
                    },
                )
                .await
                .unwrap_or_default();
                let warnings = crate::diagnose_tasks(&tasks, &agents);
                Ok(crate::TaskGraph::from_tasks(&tasks).with_diagnostics(warnings))
            }),
            Err(response) => *response,
        },
        "task.watch" => Response::error(
            req.id.clone(),
            METHOD_NOT_FOUND,
            "task.watch requires a streaming IPC connection",
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
    if params.room.is_some() {
        let runtime = match control_runtime(req) {
            Ok(runtime) => runtime,
            Err(message) => return Response::error(req.id.clone(), INTERNAL_ERROR, message),
        };
        dispatch_exec_control_result(req, runtime.block_on(crate::send_exec_stdin_matrix(params)))
    } else {
        dispatch_exec_control_result(req, crate::handle_exec_stdin_loopback(params))
    }
}

fn dispatch_exec_cancel(req: &Request, params: &crate::ExecCancelParams) -> Response {
    if params.room.is_some() {
        let runtime = match control_runtime(req) {
            Ok(runtime) => runtime,
            Err(message) => return Response::error(req.id.clone(), INTERNAL_ERROR, message),
        };
        dispatch_exec_control_result(
            req,
            runtime.block_on(crate::send_exec_cancel_matrix(params)),
        )
    } else {
        dispatch_exec_control_result(req, crate::handle_exec_cancel_loopback(params))
    }
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

fn dispatch_streaming(
    req: &Request,
    stream: &mut std::os::unix::net::UnixStream,
    pid: u32,
    started_at: u64,
    socket_path: &str,
    health: &SharedHealth,
    exec_subscribers: &crate::ExecSubscriberRegistry,
) -> io::Result<()> {
    if req.method == "task.watch" {
        dispatch_task_watch(req, stream)
    } else {
        let response = dispatch(
            req,
            pid,
            started_at,
            socket_path,
            health,
            Some(exec_subscribers),
        );
        write_ipc_response(stream, &response)
    }
}

/// Spawn the daemon as a detached background process and wait for it to report
/// readiness via the status file.
pub fn start_background() -> io::Result<RunningStatus> {
    let paths = Paths::resolve();
    paths.ensure_runtime_dir()?;

    // Fail fast (before spawning) if the runtime directory is unsafe.
    mx_agent_ipc::ensure_safe_parent_dir(&paths.runtime_dir)?;

    let exe = std::env::current_exe()?;
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log_file)?;
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
        for method in ["task.create", "task.update", "task.list", "task.graph"] {
            let req = Request::new(json!(1), method, Value::Null);
            let response = dispatch(&req, 1, now_unix(), "/tmp/daemon.sock", &None, None);
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
        let response = dispatch(&req, 1, now_unix(), "/tmp/daemon.sock", &None, None);
        let error = response.error.expect("missing session should be rejected");
        assert_eq!(error.code, INTERNAL_ERROR);
        assert!(error.message.contains("not logged in"));
    }

    #[test]
    fn exec_start_rejects_invalid_params() {
        // Missing the required `command` field.
        let req = Request::new(json!(1), "exec.start", json!({"cwd":"/tmp"}));
        let response = dispatch(&req, 1, now_unix(), "/tmp/daemon.sock", &None, None);
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
        let response = dispatch(&req, 1, now_unix(), "/tmp/daemon.sock", &None, None);
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
    fn exec_control_methods_return_structured_loopback_status() {
        let stdin_req = Request::new(
            json!(1),
            "exec.stdin",
            json!({"invocation_id":"inv_1","data":[104,105],"eof":true}),
        );
        let stdin_response = dispatch(&stdin_req, 1, now_unix(), "/tmp/daemon.sock", &None, None);
        assert!(stdin_response.error.is_none());
        let stdin: crate::ExecControlResult =
            serde_json::from_value(stdin_response.result.unwrap()).unwrap();
        assert_eq!(stdin.invocation_id, "inv_1");
        assert!(!stdin.accepted);

        let cancel_req = Request::new(
            json!(2),
            "exec.cancel",
            json!({"invocation_id":"inv_1","reason":"test"}),
        );
        let cancel_response = dispatch(&cancel_req, 1, now_unix(), "/tmp/daemon.sock", &None, None);
        assert!(cancel_response.error.is_none());
        let cancel: crate::ExecControlResult =
            serde_json::from_value(cancel_response.result.unwrap()).unwrap();
        assert_eq!(cancel.invocation_id, "inv_1");
        assert!(!cancel.accepted);
    }

    #[test]
    fn stop_when_not_running_is_idempotent() {
        let _rt = TempRuntime::new("stop");
        assert_eq!(
            stop(Duration::from_millis(200)).unwrap(),
            StopOutcome::NotRunning
        );
    }
}
