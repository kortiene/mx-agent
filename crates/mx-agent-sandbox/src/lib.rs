//! Process sandboxing backends for mx-agent remote execution.
//!
//! Backends (`none`, `bubblewrap`, container) are described in
//! `docs/architecture.md`, section 13.5. This crate defines the [`Sandbox`]
//! abstraction the process runner uses to launch a command under a chosen
//! backend, the centralized [`Restrictions`] every backend enforces, and the
//! baseline [`NoneSandbox`] implementation.
//!
//! ## The abstraction
//!
//! A [`Sandbox`] takes the requested argv plus the [`Restrictions`] resolved for
//! the request and returns a [`Prepared`] command: the argv to actually spawn
//! and the controls the runner must enforce around it. The baseline `none`
//! backend adds no isolation — it returns the argv unchanged and relies on the
//! runner enforcing the centralized controls. Stronger backends (bubblewrap,
//! container) layer isolation on top by rewriting the argv to launch the command
//! inside their wrapper; they are described in §13.5 and added later.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// Available sandbox backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// No isolation beyond cwd/env/timeout/output controls.
    None,
    /// `bubblewrap`-based isolation.
    Bubblewrap,
    /// Container-based isolation (Docker/Podman).
    Container,
}

impl Backend {
    /// The stable, lowercase name of this backend.
    ///
    /// Used to record the selected backend in the audit log (architecture
    /// §13.6) and to match the policy configuration vocabulary (§13.5).
    pub fn name(self) -> &'static str {
        match self {
            Backend::None => "none",
            Backend::Bubblewrap => "bubblewrap",
            Backend::Container => "container",
        }
    }
}

/// Default sandbox backend used until configured otherwise.
pub fn default_backend() -> Backend {
    Backend::None
}

/// The baseline execution controls every sandbox backend enforces around a
/// command (architecture §13.5 "minimum controls"): a restricted working
/// directory, a sanitized environment, a wall-clock timeout, and an output cap.
///
/// Centralizing these here gives every backend — and the process runner — one
/// vocabulary for the baseline controls. The `none` backend relies on the
/// runner enforcing them as-is; stronger backends may tighten them further (for
/// example a container backend rewriting `cwd` to its in-container path) before
/// layering additional isolation on top.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Restrictions {
    /// Working directory the command must run in (an allowed cwd).
    pub cwd: PathBuf,
    /// The sanitized environment handed to the command. Secrets are already
    /// scrubbed by the caller (architecture §13.4); a backend may restrict this
    /// further but must never widen it.
    pub env: BTreeMap<String, String>,
    /// Maximum wall-clock runtime, if capped. `None` runs with no enforced
    /// limit. Enforced by the runner, which terminates the process group on
    /// expiry (§7.4).
    pub timeout: Option<Duration>,
    /// Maximum captured output in bytes, if capped. `None` captures without an
    /// enforced limit. Enforced by the output-capture stage, not the spawn
    /// itself; carried here so the full baseline control set lives in one place.
    pub max_output_bytes: Option<u64>,
}

/// A command prepared for execution by a [`Sandbox`] backend.
///
/// Returned by [`Sandbox::prepare`]: the argv to actually spawn, the controls
/// the runner must enforce around it, and the backend that prepared it (recorded
/// in the audit log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// The backend that prepared this command.
    pub backend: Backend,
    /// The argv to spawn. For `none` this is the requested argv unchanged; an
    /// isolating backend prepends its launcher (e.g. `bwrap … -- <argv>`).
    pub argv: Vec<String>,
    /// The controls the runner must enforce around the spawned process.
    pub restrictions: Restrictions,
}

/// A process isolation backend (architecture §13.5).
///
/// Given the requested argv and the [`Restrictions`] resolved for a request, a
/// backend returns a [`Prepared`] command describing what to spawn and which
/// controls to enforce. Implementations are pure so the wrapping rules can be
/// unit-tested without spawning anything.
pub trait Sandbox {
    /// Which backend this implementation is.
    fn backend(&self) -> Backend;

    /// Prepare `argv` for execution under this backend with `restrictions`.
    fn prepare(&self, argv: Vec<String>, restrictions: Restrictions) -> Prepared;
}

/// The baseline `none` backend: no isolation beyond the centralized
/// [`Restrictions`].
///
/// It returns the requested argv unchanged and relies on the process runner to
/// enforce the restricted cwd, sanitized env, timeout, and output cap. This is
/// the default until a stronger backend is configured (architecture §13.5).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoneSandbox;

impl Sandbox for NoneSandbox {
    fn backend(&self) -> Backend {
        Backend::None
    }

    fn prepare(&self, argv: Vec<String>, restrictions: Restrictions) -> Prepared {
        Prepared {
            backend: Backend::None,
            argv,
            restrictions,
        }
    }
}

/// Construct the sandbox implementation for `backend`.
///
/// Only the baseline [`Backend::None`] is implemented today. The stronger
/// backends are described in §13.5 and not yet available, so they fall back to
/// the `none` backend; the returned [`Prepared::backend`] then truthfully
/// reports `none`, so the audit log never claims isolation that was not applied.
pub fn sandbox_for(backend: Backend) -> Box<dyn Sandbox> {
    match backend {
        Backend::None => Box::new(NoneSandbox),
        // Not yet implemented (issue #53 ships only the baseline): fall back to
        // `none` rather than failing, and report `none` honestly.
        Backend::Bubblewrap | Backend::Container => Box::new(NoneSandbox),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_backend_is_none() {
        assert_eq!(default_backend(), Backend::None);
    }

    #[test]
    fn backend_names_are_stable() {
        assert_eq!(Backend::None.name(), "none");
        assert_eq!(Backend::Bubblewrap.name(), "bubblewrap");
        assert_eq!(Backend::Container.name(), "container");
    }

    #[test]
    fn none_backend_runs_argv_unchanged() {
        let restrictions = Restrictions {
            cwd: PathBuf::from("/work"),
            timeout: Some(Duration::from_secs(30)),
            max_output_bytes: Some(1024),
            ..Restrictions::default()
        };
        let prepared = NoneSandbox.prepare(argv(&["echo", "hi"]), restrictions.clone());
        assert_eq!(prepared.backend, Backend::None);
        // No isolation: the argv is passed through verbatim.
        assert_eq!(prepared.argv, argv(&["echo", "hi"]));
        // The centralized controls are carried through unchanged.
        assert_eq!(prepared.restrictions, restrictions);
    }

    #[test]
    fn sandbox_for_none_reports_none() {
        let sandbox = sandbox_for(Backend::None);
        assert_eq!(sandbox.backend(), Backend::None);
    }

    #[test]
    fn unimplemented_backends_fall_back_to_none_honestly() {
        // Until the stronger backends land, selection falls back to `none` and
        // the prepared command reports `none` so the audit log stays truthful.
        for requested in [Backend::Bubblewrap, Backend::Container] {
            let prepared = sandbox_for(requested).prepare(argv(&["true"]), Restrictions::default());
            assert_eq!(prepared.backend, Backend::None);
            assert_eq!(prepared.argv, argv(&["true"]));
        }
    }
}
