//! The curated default-deny seccomp-bpf profile (issue #380), `cfg(target_os = "linux")`.
//!
//! Seccomp is a Linux-only confinement floor that narrows the kernel attack
//! surface an *already-authorized* command can reach. This module is the single
//! source of truth for mx-agent's built-in profile: one syscall allowlist,
//! expressed once, from which both representations are derived so they cannot
//! drift —
//!
//! - [`default_bpf_program`] compiles the allowlist into a `seccompiler`
//!   [`BpfProgram`] for in-process installation (the `none` launcher path) and,
//!   after [`serialize_bpf_program`], for `bwrap --seccomp <fd>` (the bubblewrap
//!   path);
//! - [`default_profile_json`] renders the equivalent OCI seccomp profile string
//!   for the container path's `--security-opt seccomp=<path>`.
//!
//! The profile's *default* (mismatch) action is `ERRNO(EPERM)` — matching the
//! [`SeccompMode::Default`][crate::SeccompMode::Default] contract — so a
//! too-strict profile degrades to a recoverable command failure rather than an
//! opaque `SIGSYS` death. Every listed syscall is allowed unconditionally
//! (argument-independent). The allowlist is modeled on the proven Docker/Podman
//! default profile, broad enough to run the real build/test command corpus
//! (`sh`, `cargo`, `rustc`, `make`, `git`, `cc`, `ld`, …) yet narrow enough to
//! confine.
//!
//! The module is absent on non-Linux targets; callers `cfg`-gate to a no-op.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

/// An error building, compiling, or writing the default-deny seccomp profile.
///
/// Surfaced fail-closed by the callers (the launcher returns it instead of
/// `exec`-ing unfiltered; the runner fails the spawn), so a profile that cannot
/// be installed never silently degrades to running a command unconfined.
#[derive(Debug)]
pub enum SeccompError {
    /// The host architecture is not one `seccompiler` can target (only
    /// little-endian x86_64 / aarch64 / riscv64 are supported). The contained
    /// string is the offending [`std::env::consts::ARCH`].
    UnsupportedArch(&'static str),
    /// `seccompiler` failed to build or compile the filter into a BPF program.
    Build(seccompiler::BackendError),
    /// Writing the OCI profile file for the container backend failed.
    Write(io::Error),
}

impl fmt::Display for SeccompError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArch(arch) => {
                write!(f, "seccomp is not supported on this architecture ({arch})")
            }
            Self::Build(e) => write!(f, "could not build the seccomp BPF program: {e}"),
            Self::Write(e) => write!(f, "could not write the seccomp profile: {e}"),
        }
    }
}

impl std::error::Error for SeccompError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Build(e) => Some(e),
            Self::Write(e) => Some(e),
            Self::UnsupportedArch(_) => None,
        }
    }
}

impl From<seccompiler::BackendError> for SeccompError {
    fn from(e: seccompiler::BackendError) -> Self {
        Self::Build(e)
    }
}

/// One allowlisted syscall: its kernel name (for the OCI JSON profile, keyed by
/// name) and its number on the *current* target arch (for the BPF program, keyed
/// by number). Both views are derived from the same table, so they cannot drift.
struct Allowed {
    /// The syscall's stable kernel name (e.g. `"openat"`).
    name: &'static str,
    /// The syscall's number on the current target arch (`libc::SYS_*`).
    number: libc::c_long,
}

/// The canonical syscall allowlist, modeled on the Docker/Podman default profile.
///
/// `libc::SYS_*` resolves per target arch, so x86_64 and aarch64 stay correct
/// automatically. The unconditional entries exist on both x86_64 and aarch64; the
/// `target_arch = "x86_64"` block adds the legacy (non-`*at`) variants that exist
/// only there — aarch64 tooling uses the modern variants already in the common
/// set. The list deliberately includes the process-startup/exec set the
/// kernel/libc/loader need *after* the filter is active (`execve`/`execveat`,
/// `mmap`/`mprotect`/`munmap`, `brk`, `clone`/`clone3`, `futex`, the signal-setup
/// calls, `exit`/`exit_group`) so the subsequent `exec` and the target's own
/// startup succeed.
fn allowlist() -> Vec<Allowed> {
    let mut v = Vec::new();
    macro_rules! allow {
        ($name:literal, $sys:expr) => {
            v.push(Allowed {
                name: $name,
                number: $sys,
            });
        };
    }

    // --- I/O and file descriptors --------------------------------------------
    allow!("read", libc::SYS_read);
    allow!("write", libc::SYS_write);
    allow!("close", libc::SYS_close);
    allow!("close_range", libc::SYS_close_range);
    allow!("openat", libc::SYS_openat);
    allow!("openat2", libc::SYS_openat2);
    allow!("lseek", libc::SYS_lseek);
    allow!("pread64", libc::SYS_pread64);
    allow!("pwrite64", libc::SYS_pwrite64);
    allow!("readv", libc::SYS_readv);
    allow!("writev", libc::SYS_writev);
    allow!("preadv", libc::SYS_preadv);
    allow!("pwritev", libc::SYS_pwritev);
    allow!("preadv2", libc::SYS_preadv2);
    allow!("pwritev2", libc::SYS_pwritev2);
    allow!("pipe2", libc::SYS_pipe2);
    allow!("dup", libc::SYS_dup);
    allow!("dup3", libc::SYS_dup3);
    allow!("fcntl", libc::SYS_fcntl);
    allow!("flock", libc::SYS_flock);
    allow!("fsync", libc::SYS_fsync);
    allow!("fdatasync", libc::SYS_fdatasync);
    allow!("ftruncate", libc::SYS_ftruncate);
    allow!("truncate", libc::SYS_truncate);
    allow!("getdents64", libc::SYS_getdents64);
    allow!("splice", libc::SYS_splice);
    allow!("tee", libc::SYS_tee);
    allow!("ioctl", libc::SYS_ioctl);

    // --- filesystem metadata / namespace -------------------------------------
    allow!("getcwd", libc::SYS_getcwd);
    allow!("chdir", libc::SYS_chdir);
    allow!("fchdir", libc::SYS_fchdir);
    allow!("renameat2", libc::SYS_renameat2);
    allow!("mkdirat", libc::SYS_mkdirat);
    allow!("unlinkat", libc::SYS_unlinkat);
    allow!("symlinkat", libc::SYS_symlinkat);
    allow!("linkat", libc::SYS_linkat);
    allow!("readlinkat", libc::SYS_readlinkat);
    allow!("fchmodat", libc::SYS_fchmodat);
    allow!("fchmod", libc::SYS_fchmod);
    allow!("fchownat", libc::SYS_fchownat);
    allow!("fchown", libc::SYS_fchown);
    allow!("faccessat", libc::SYS_faccessat);
    allow!("faccessat2", libc::SYS_faccessat2);
    allow!("newfstatat", libc::SYS_newfstatat);
    allow!("fstat", libc::SYS_fstat);
    allow!("statx", libc::SYS_statx);
    allow!("statfs", libc::SYS_statfs);
    allow!("fstatfs", libc::SYS_fstatfs);
    allow!("utimensat", libc::SYS_utimensat);
    allow!("umask", libc::SYS_umask);
    allow!("mknodat", libc::SYS_mknodat);

    // --- memory ---------------------------------------------------------------
    allow!("mmap", libc::SYS_mmap);
    allow!("munmap", libc::SYS_munmap);
    allow!("mremap", libc::SYS_mremap);
    allow!("mprotect", libc::SYS_mprotect);
    allow!("madvise", libc::SYS_madvise);
    allow!("msync", libc::SYS_msync);
    allow!("mlock", libc::SYS_mlock);
    allow!("munlock", libc::SYS_munlock);
    allow!("brk", libc::SYS_brk);

    // --- signals --------------------------------------------------------------
    allow!("rt_sigaction", libc::SYS_rt_sigaction);
    allow!("rt_sigprocmask", libc::SYS_rt_sigprocmask);
    allow!("rt_sigreturn", libc::SYS_rt_sigreturn);
    allow!("rt_sigpending", libc::SYS_rt_sigpending);
    allow!("rt_sigtimedwait", libc::SYS_rt_sigtimedwait);
    allow!("rt_sigsuspend", libc::SYS_rt_sigsuspend);
    allow!("rt_sigqueueinfo", libc::SYS_rt_sigqueueinfo);
    allow!("sigaltstack", libc::SYS_sigaltstack);

    // --- process lifecycle (build/test spawn subprocesses) -------------------
    allow!("clone", libc::SYS_clone);
    allow!("clone3", libc::SYS_clone3);
    allow!("execve", libc::SYS_execve);
    allow!("execveat", libc::SYS_execveat);
    allow!("exit", libc::SYS_exit);
    allow!("exit_group", libc::SYS_exit_group);
    allow!("wait4", libc::SYS_wait4);
    allow!("waitid", libc::SYS_waitid);
    allow!("kill", libc::SYS_kill);
    allow!("tkill", libc::SYS_tkill);
    allow!("tgkill", libc::SYS_tgkill);
    allow!("set_tid_address", libc::SYS_set_tid_address);
    allow!("set_robust_list", libc::SYS_set_robust_list);
    allow!("get_robust_list", libc::SYS_get_robust_list);
    allow!("futex", libc::SYS_futex);
    allow!("rseq", libc::SYS_rseq);
    allow!("membarrier", libc::SYS_membarrier);
    allow!("restart_syscall", libc::SYS_restart_syscall);

    // --- time -----------------------------------------------------------------
    allow!("nanosleep", libc::SYS_nanosleep);
    allow!("clock_nanosleep", libc::SYS_clock_nanosleep);
    allow!("clock_gettime", libc::SYS_clock_gettime);
    allow!("clock_getres", libc::SYS_clock_getres);
    allow!("gettimeofday", libc::SYS_gettimeofday);
    allow!("getrandom", libc::SYS_getrandom);

    // --- process / system introspection --------------------------------------
    allow!("uname", libc::SYS_uname);
    allow!("sysinfo", libc::SYS_sysinfo);
    allow!("getpid", libc::SYS_getpid);
    allow!("getppid", libc::SYS_getppid);
    allow!("gettid", libc::SYS_gettid);
    allow!("getuid", libc::SYS_getuid);
    allow!("geteuid", libc::SYS_geteuid);
    allow!("getgid", libc::SYS_getgid);
    allow!("getegid", libc::SYS_getegid);
    allow!("getgroups", libc::SYS_getgroups);
    allow!("setgroups", libc::SYS_setgroups);
    allow!("getpgid", libc::SYS_getpgid);
    allow!("setpgid", libc::SYS_setpgid);
    allow!("getsid", libc::SYS_getsid);
    allow!("setsid", libc::SYS_setsid);
    allow!("getpriority", libc::SYS_getpriority);
    allow!("setpriority", libc::SYS_setpriority);
    allow!("sched_getaffinity", libc::SYS_sched_getaffinity);
    allow!("sched_setaffinity", libc::SYS_sched_setaffinity);
    allow!("sched_yield", libc::SYS_sched_yield);
    allow!("sched_getparam", libc::SYS_sched_getparam);
    allow!("sched_getscheduler", libc::SYS_sched_getscheduler);
    allow!("prctl", libc::SYS_prctl);
    allow!("prlimit64", libc::SYS_prlimit64);
    allow!("getrusage", libc::SYS_getrusage);
    allow!("times", libc::SYS_times);
    allow!("capget", libc::SYS_capget);

    // --- poll / event fds -----------------------------------------------------
    allow!("epoll_create1", libc::SYS_epoll_create1);
    allow!("epoll_ctl", libc::SYS_epoll_ctl);
    allow!("epoll_pwait", libc::SYS_epoll_pwait);
    allow!("epoll_pwait2", libc::SYS_epoll_pwait2);
    allow!("ppoll", libc::SYS_ppoll);
    allow!("pselect6", libc::SYS_pselect6);
    allow!("eventfd2", libc::SYS_eventfd2);
    allow!("signalfd4", libc::SYS_signalfd4);
    allow!("timerfd_create", libc::SYS_timerfd_create);
    allow!("timerfd_settime", libc::SYS_timerfd_settime);
    allow!("timerfd_gettime", libc::SYS_timerfd_gettime);
    allow!("inotify_init1", libc::SYS_inotify_init1);
    allow!("inotify_add_watch", libc::SYS_inotify_add_watch);
    allow!("inotify_rm_watch", libc::SYS_inotify_rm_watch);
    allow!("memfd_create", libc::SYS_memfd_create);
    allow!("pidfd_open", libc::SYS_pidfd_open);
    allow!("pidfd_send_signal", libc::SYS_pidfd_send_signal);

    // --- local sockets (build tooling talks to local daemons over AF_UNIX) ---
    allow!("socket", libc::SYS_socket);
    allow!("socketpair", libc::SYS_socketpair);
    allow!("connect", libc::SYS_connect);
    allow!("bind", libc::SYS_bind);
    allow!("listen", libc::SYS_listen);
    allow!("accept", libc::SYS_accept);
    allow!("accept4", libc::SYS_accept4);
    allow!("getsockname", libc::SYS_getsockname);
    allow!("getpeername", libc::SYS_getpeername);
    allow!("getsockopt", libc::SYS_getsockopt);
    allow!("setsockopt", libc::SYS_setsockopt);
    allow!("sendto", libc::SYS_sendto);
    allow!("recvfrom", libc::SYS_recvfrom);
    allow!("sendmsg", libc::SYS_sendmsg);
    allow!("recvmsg", libc::SYS_recvmsg);
    allow!("shutdown", libc::SYS_shutdown);

    // --- legacy (non-`*at`) variants that exist only on x86_64; aarch64 uses
    //     the modern variants already in the common set above ------------------
    #[cfg(target_arch = "x86_64")]
    {
        allow!("open", libc::SYS_open);
        allow!("stat", libc::SYS_stat);
        allow!("lstat", libc::SYS_lstat);
        allow!("poll", libc::SYS_poll);
        allow!("select", libc::SYS_select);
        allow!("access", libc::SYS_access);
        allow!("pipe", libc::SYS_pipe);
        allow!("dup2", libc::SYS_dup2);
        allow!("rename", libc::SYS_rename);
        allow!("renameat", libc::SYS_renameat);
        allow!("mkdir", libc::SYS_mkdir);
        allow!("rmdir", libc::SYS_rmdir);
        allow!("unlink", libc::SYS_unlink);
        allow!("symlink", libc::SYS_symlink);
        allow!("link", libc::SYS_link);
        allow!("readlink", libc::SYS_readlink);
        allow!("chmod", libc::SYS_chmod);
        allow!("chown", libc::SYS_chown);
        allow!("creat", libc::SYS_creat);
        allow!("getdents", libc::SYS_getdents);
        allow!("epoll_create", libc::SYS_epoll_create);
        allow!("epoll_wait", libc::SYS_epoll_wait);
        allow!("eventfd", libc::SYS_eventfd);
        allow!("signalfd", libc::SYS_signalfd);
        allow!("inotify_init", libc::SYS_inotify_init);
        allow!("alarm", libc::SYS_alarm);
        allow!("pause", libc::SYS_pause);
        allow!("time", libc::SYS_time);
        allow!("getpgrp", libc::SYS_getpgrp);
        allow!("utimes", libc::SYS_utimes);
        allow!("futimesat", libc::SYS_futimesat);
        allow!("arch_prctl", libc::SYS_arch_prctl);
        // `sendfile` exists on aarch64 too, but libc only binds `SYS_sendfile`
        // for x86_64; reference it only where the constant is defined.
        allow!("sendfile", libc::SYS_sendfile);
    }

    v
}

/// Resolve the `seccompiler` [`TargetArch`] for the current build, failing
/// loudly on an architecture it cannot target rather than installing a
/// wrong-arch filter.
fn target_arch() -> Result<TargetArch, SeccompError> {
    TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|_| SeccompError::UnsupportedArch(std::env::consts::ARCH))
}

/// The errno a denied (non-allowlisted) syscall returns under the default
/// profile: `EPERM`, not a `KILL`, so a too-strict profile degrades to a
/// recoverable command failure.
fn default_errno() -> u32 {
    libc::EPERM as u32
}

/// Compile the curated default-deny allowlist into a `seccompiler`
/// [`BpfProgram`] for the current architecture.
///
/// The default (mismatch) action is `ERRNO(EPERM)` and every allowlisted syscall
/// matches unconditionally (`Allow`). Install it in-process with the safe
/// [`seccompiler::apply_filter`] (the `none` launcher path) or serialize it with
/// [`serialize_bpf_program`] for `bwrap --seccomp <fd>` (the bubblewrap path).
pub fn default_bpf_program() -> Result<BpfProgram, SeccompError> {
    let arch = target_arch()?;
    let rules: BTreeMap<i64, Vec<SeccompRule>> = allowlist()
        .into_iter()
        .map(|s| (s.number as i64, Vec::new()))
        .collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(default_errno()),
        SeccompAction::Allow,
        arch,
    )?;
    let program: BpfProgram = filter.try_into()?;
    Ok(program)
}

/// Serialize a compiled [`BpfProgram`] to the raw `struct sock_filter[]` byte
/// layout that `bwrap --seccomp <fd>` reads from a file descriptor.
///
/// Each instruction is the kernel's 8-byte `sock_filter` (`u16 code; u8 jt; u8
/// jf; u32 k`) in native byte order; `seccompiler` only builds on little-endian
/// hosts, so native order is what `bwrap`'s `sock_fprog` expects. No `unsafe`:
/// the fields are packed individually rather than reinterpreting the struct's
/// memory.
pub fn serialize_bpf_program(program: &BpfProgram) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(program.len() * 8);
    for insn in program {
        bytes.extend_from_slice(&insn.code.to_ne_bytes());
        bytes.push(insn.jt);
        bytes.push(insn.jf);
        bytes.extend_from_slice(&insn.k.to_ne_bytes());
    }
    bytes
}

/// The architecture tags emitted in the OCI profile's `architectures` array for
/// the current build, mirroring how the Docker/Podman default profile groups a
/// primary arch with its compatibility sub-architectures.
fn oci_architectures() -> Vec<&'static str> {
    #[cfg(target_arch = "x86_64")]
    {
        vec!["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"]
    }
    #[cfg(target_arch = "aarch64")]
    {
        vec!["SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM"]
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Vec::new()
    }
}

/// Render the equivalent OCI seccomp profile (the JSON the container backend
/// passes via `--security-opt seccomp=<path>`) from the *same* allowlist as
/// [`default_bpf_program`], so the two cannot drift.
///
/// `defaultAction` is `SCMP_ACT_ERRNO` (returning `EPERM`); the allowlisted
/// syscall names are listed in a single `SCMP_ACT_ALLOW` block. Docker and
/// Podman already apply a built-in default profile unless `--privileged`;
/// shipping this explicit profile makes the filter independent of the host
/// runtime's default and consistent with the `none`/bubblewrap paths.
pub fn default_profile_json() -> String {
    let names: Vec<&str> = allowlist().iter().map(|s| s.name).collect();
    let profile = serde_json::json!({
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": default_errno(),
        "architectures": oci_architectures(),
        "syscalls": [
            {
                "names": names,
                "action": "SCMP_ACT_ALLOW",
            }
        ],
    });
    serde_json::to_string_pretty(&profile).expect("the seccomp profile is always valid JSON")
}

/// Write the OCI seccomp profile to `dir/seccomp-default.json` (world-unwritable,
/// `0644`) and return its path, for the container backend's
/// `--security-opt seccomp=<path>`.
///
/// `0644` lets the runtime process read it — rootless podman runs as the invoking
/// uid — while keeping it owner-write only. The file is rewritten on each call so
/// a stale or missing profile self-heals.
pub fn write_default_profile(dir: &Path) -> Result<PathBuf, SeccompError> {
    let path = dir.join("seccomp-default.json");
    std::fs::write(&path, default_profile_json()).map_err(SeccompError::Write)?;
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .map_err(SeccompError::Write)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_includes_mandatory_startup_syscalls() {
        // The exec/startup set the kernel/libc/loader need after the filter is
        // active must be present, or the subsequent `exec` (and the target's own
        // startup) would be denied and the command could never run.
        let names: std::collections::BTreeSet<&str> = allowlist().iter().map(|s| s.name).collect();
        for required in [
            "execve",
            "execveat",
            "mmap",
            "mprotect",
            "munmap",
            "brk",
            "openat",
            "read",
            "write",
            "close",
            "rt_sigaction",
            "rt_sigprocmask",
            "set_tid_address",
            "set_robust_list",
            "futex",
            "clone",
            "clone3",
            "wait4",
            "exit",
            "exit_group",
        ] {
            assert!(
                names.contains(required),
                "allowlist must include {required}"
            );
        }
    }

    #[test]
    fn default_bpf_program_builds_and_compiles() {
        // Acceptance (issue #380): the curated profile compiles to a BPF program
        // on the supported arches without error (EPERM default vs Allow match are
        // distinct, the arch resolves, the rules are well-formed).
        let program = default_bpf_program().expect("default profile compiles");
        assert!(
            !program.is_empty(),
            "a compiled allowlist BPF program is never empty"
        );
        // Serialization is the exact 8-byte-per-instruction sock_filter layout.
        let bytes = serialize_bpf_program(&program);
        assert_eq!(bytes.len(), program.len() * 8);
    }

    #[test]
    fn bpf_table_and_json_names_are_identical() {
        // Drift guard over the single source of truth: the BPF program is keyed by
        // number and the OCI JSON by name, but both derive from `allowlist()`, so
        // the JSON's name set must equal the table's name set exactly.
        let table_names: std::collections::BTreeSet<&str> =
            allowlist().iter().map(|s| s.name).collect();

        let json: serde_json::Value =
            serde_json::from_str(&default_profile_json()).expect("profile is valid JSON");
        let json_names: std::collections::BTreeSet<&str> = json["syscalls"][0]["names"]
            .as_array()
            .expect("names array")
            .iter()
            .map(|v| v.as_str().expect("name is a string"))
            .collect();

        assert_eq!(
            table_names, json_names,
            "the BPF table and the OCI JSON must cover identical syscalls"
        );
    }

    #[test]
    fn json_profile_is_default_deny_errno() {
        let json: serde_json::Value =
            serde_json::from_str(&default_profile_json()).expect("profile is valid JSON");
        assert_eq!(json["defaultAction"], "SCMP_ACT_ERRNO");
        assert_eq!(json["defaultErrnoRet"], libc::EPERM);
        assert_eq!(json["syscalls"][0]["action"], "SCMP_ACT_ALLOW");
        assert!(
            !json["architectures"]
                .as_array()
                .expect("arch array")
                .is_empty(),
            "the profile must name at least the host architecture"
        );
    }

    #[test]
    fn write_default_profile_writes_readable_file() {
        let dir = std::env::temp_dir().join(format!("mx-agent-seccomp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create dir");
        let path = write_default_profile(&dir).expect("write profile");
        assert_eq!(path, dir.join("seccomp-default.json"));
        let written = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(written, default_profile_json());
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o644,
            "profile must be 0644 (owner-write only)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_default_profile_overwrites_existing_file() {
        // Self-heal: a second write must succeed even if the file already exists
        // with stale or missing content (the doc says "the file is rewritten on
        // each call so a stale or missing profile self-heals").
        let dir =
            std::env::temp_dir().join(format!("mx-agent-seccomp-overwrite-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create dir");
        let path = dir.join("seccomp-default.json");
        std::fs::write(&path, b"stale content").expect("seed stale file");
        let written_path = write_default_profile(&dir).expect("second write must succeed");
        assert_eq!(written_path, path);
        let content = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(
            content,
            default_profile_json(),
            "stale content must be replaced"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlist_has_no_duplicate_names() {
        // A duplicate syscall name in the allowlist would make the OCI JSON
        // `names` array contain the same string twice, while the BPF BTreeMap
        // silently deduplicates by syscall number — breaking the drift guard.
        // (The existing bpf_table_and_json_names_are_identical test uses BTreeSet
        // for both sides and thus also deduplicates, masking any such bug.)
        let names: Vec<&str> = allowlist().iter().map(|s| s.name).collect();
        let unique: std::collections::BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(
            names.len(),
            unique.len(),
            "allowlist must not contain duplicate syscall names"
        );
    }

    #[test]
    fn allowlist_has_no_duplicate_numbers() {
        // A duplicate syscall number would cause the BpfProgram's BTreeMap to
        // silently merge the two entries, losing the second one without warning.
        let numbers: Vec<libc::c_long> = allowlist().iter().map(|s| s.number).collect();
        let unique: std::collections::BTreeSet<libc::c_long> = numbers.iter().copied().collect();
        assert_eq!(
            numbers.len(),
            unique.len(),
            "allowlist must not contain duplicate syscall numbers"
        );
    }

    #[test]
    fn seccomp_error_write_display_names_the_cause() {
        // SeccompError::Write wraps an io::Error; Display must include enough
        // context that an operator can identify the failure ("could not write").
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let err = SeccompError::Write(io_err);
        let msg = err.to_string();
        assert!(
            msg.contains("could not write"),
            "Write display must mention 'could not write': {msg}"
        );
    }

    #[test]
    fn seccomp_error_unsupported_arch_display_names_the_arch() {
        // UnsupportedArch must name the offending arch in its Display so an
        // operator running on an unusual target knows what was rejected.
        let err = SeccompError::UnsupportedArch("mips");
        let msg = err.to_string();
        assert!(
            msg.contains("mips"),
            "UnsupportedArch display must name the arch: {msg}"
        );
        assert!(
            msg.contains("not supported") || msg.contains("unsupported"),
            "UnsupportedArch display must say seccomp is unsupported: {msg}"
        );
    }

    #[test]
    fn seccomp_error_source_impl() {
        use std::error::Error as _;
        // UnsupportedArch has no underlying cause — source() must return None.
        let err = SeccompError::UnsupportedArch("mips");
        assert!(
            err.source().is_none(),
            "UnsupportedArch must have no source error"
        );
        // Write wraps an io::Error; source() must expose the wrapped error.
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err = SeccompError::Write(io_err);
        assert!(
            err.source().is_some(),
            "Write variant must expose the wrapped io::Error via source()"
        );
    }

    #[test]
    fn serialize_bpf_program_is_deterministic() {
        // Two compilations of the same allowlist must produce byte-identical
        // output: no HashMap/HashSet ordering non-determinism must leak into the
        // BPF byte stream.
        let p1 = default_bpf_program().expect("first compile");
        let p2 = default_bpf_program().expect("second compile");
        assert_eq!(
            serialize_bpf_program(&p1),
            serialize_bpf_program(&p2),
            "serialize_bpf_program must be deterministic across two calls"
        );
    }

    #[test]
    fn allowlist_is_nonempty() {
        // Sanity guard: a completely empty allowlist would deny every syscall
        // (including exit/exit_group), making the target command impossible to run.
        assert!(
            !allowlist().is_empty(),
            "the syscall allowlist must not be empty"
        );
    }
}
