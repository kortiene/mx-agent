//! Centralized resolution of the operator policy file (issue #350).
//!
//! Every daemon enforcement point authorizes against the local policy. A
//! *missing* `policy.toml` is the intended deny-all default and must stay
//! silent (the daemon must run before login and before any policy exists), but a
//! *present but unusable* file (broken TOML, failed validation, or an unreadable
//! file) previously degraded to the same deny-all default with no signal —
//! outwardly indistinguishable from "policy applied and everything happens to be
//! denied."
//!
//! This module distinguishes the two and gives every call site one place to fail
//! loudly on a malformed policy while preserving the fail-closed (deny-all)
//! authorization outcome. The distinction surfaces through three independent loud
//! signals: a refuse-to-start gate at boot ([`crate::lifecycle`]), an
//! `error`-level log at each lazy enforcement load
//! ([`resolve_policy_for_enforcement`]), and a persistent `daemon status` warning
//! ([`PolicyStatus`]).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use mx_agent_policy::Policy;

/// The single malformed-policy state surfaced through `daemon.status`. Healthy
/// and absent policies are represented by the *absence* of a [`PolicyStatus`].
pub const POLICY_STATE_MALFORMED: &str = "malformed";

/// Outcome of resolving the operator policy file.
#[derive(Debug)]
pub enum PolicyResolution {
    /// No policy file present (or no config dir to look in) — the deny-all
    /// default applies. This is the correct, silent fallback.
    Absent,
    /// Policy file present, parsed, and validated.
    Loaded(Policy),
    /// Policy file present but unreadable / unparseable / invalid.
    ///
    /// Authorization still uses the deny-all default (fail-closed), but this is
    /// an error state that callers must surface loudly (issue #350).
    Malformed {
        /// Path of the offending policy file.
        path: PathBuf,
        /// Operator-facing diagnostic from [`mx_agent_policy::PolicyError`]'s
        /// `Display` (file path, TOML location, or dotted validation field).
        display: String,
    },
}

impl PolicyResolution {
    /// The policy to authorize against: the loaded policy, or the deny-all
    /// default for both the absent and malformed cases (fail-closed).
    pub fn into_policy(self) -> Policy {
        match self {
            PolicyResolution::Loaded(policy) => policy,
            PolicyResolution::Absent | PolicyResolution::Malformed { .. } => Policy::default(),
        }
    }

    /// `Some(human message)` when the policy is malformed, else `None`.
    ///
    /// The message names the file path and the underlying failure, ready to log
    /// or return to an operator. No secrets are involved — `policy.toml` is
    /// non-sensitive config and the diagnostic never includes file contents.
    pub fn malformed_message(&self) -> Option<String> {
        match self {
            PolicyResolution::Malformed { path, display } => {
                Some(format!("malformed policy {}: {display}", path.display()))
            }
            PolicyResolution::Absent | PolicyResolution::Loaded(_) => None,
        }
    }

    /// The structured health record for `daemon.status`, present only when the
    /// policy is malformed. Absent/healthy policies return `None`, keeping the
    /// status payload backward-compatible.
    pub fn status(&self) -> Option<PolicyStatus> {
        match self {
            PolicyResolution::Malformed { path, display } => Some(PolicyStatus {
                state: POLICY_STATE_MALFORMED.to_string(),
                path: path.display().to_string(),
                error: display.clone(),
            }),
            PolicyResolution::Absent | PolicyResolution::Loaded(_) => None,
        }
    }
}

/// Operator-policy health surfaced through `daemon.status` (issue #350).
///
/// Present only when the policy file is unusable; a healthy or absent policy is
/// represented by `RunningStatus.policy == None`, so the status payload is
/// unchanged for healthy daemons and backward-compatible with older consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyStatus {
    /// Health state. Currently always [`POLICY_STATE_MALFORMED`].
    pub state: String,
    /// Path of the offending policy file.
    pub path: String,
    /// Operator-facing diagnostic naming the failure (and, for validation
    /// errors, the dotted field path the policy crate produces).
    pub error: String,
}

/// Resolve the operator policy from its default path without side effects.
///
/// Returns [`PolicyResolution::Absent`] when no config dir can be determined or
/// the file is missing, [`PolicyResolution::Loaded`] when it parses and
/// validates, and [`PolicyResolution::Malformed`] when it is present but
/// unusable. Emits no logs; callers decide how loudly to surface the outcome.
pub fn resolve_policy() -> PolicyResolution {
    match Policy::default_path() {
        // No config dir → there is no file that could be malformed.
        None => PolicyResolution::Absent,
        Some(path) => match Policy::load_optional(&path) {
            Ok(None) => PolicyResolution::Absent,
            Ok(Some(policy)) => PolicyResolution::Loaded(policy),
            Err(e) => PolicyResolution::Malformed {
                path,
                display: e.to_string(),
            },
        },
    }
}

/// Resolve the policy for an enforcement pass and return the policy to authorize
/// against.
///
/// Like [`resolve_policy`], but emits a single `error`-level log when the policy
/// is malformed so a runtime breakage is never silent in the daemon log. The
/// returned policy is the deny-all default on both the absent and malformed
/// cases (fail-closed); only a present, valid file authorizes anything. `context`
/// labels the enforcement site in the log (e.g. `"exec.authorize"`).
pub fn resolve_policy_for_enforcement(context: &str) -> Policy {
    let resolution = resolve_policy();
    if let Some(msg) = resolution.malformed_message() {
        tracing::error!(
            context,
            %msg,
            "policy file is present but unusable; authorizing nothing (deny-all) until it is fixed"
        );
    }
    resolution.into_policy()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mx_agent_policy::NetworkPolicy;

    // ── Pure unit tests for PolicyResolution methods ─────────────────────────

    fn malformed(path: &str, error: &str) -> PolicyResolution {
        PolicyResolution::Malformed {
            path: std::path::PathBuf::from(path),
            display: error.to_string(),
        }
    }

    #[test]
    fn absent_into_policy_is_default() {
        let policy = PolicyResolution::Absent.into_policy();
        assert!(
            policy.rooms.is_empty(),
            "Absent must resolve to the deny-all default (no rooms)"
        );
    }

    #[test]
    fn loaded_into_policy_returns_it() {
        let loaded =
            Policy::parse("[execution]\nnetwork = \"allow\"\n").expect("valid policy parses");
        let policy = PolicyResolution::Loaded(loaded).into_policy();
        assert_eq!(
            policy.execution.network,
            Some(NetworkPolicy::Allow),
            "Loaded must return the actual policy"
        );
    }

    #[test]
    fn malformed_into_policy_is_default() {
        let policy = malformed("/etc/mx-agent/policy.toml", "parse error").into_policy();
        assert!(
            policy.rooms.is_empty(),
            "Malformed must resolve to the deny-all default (fail-closed)"
        );
    }

    #[test]
    fn absent_malformed_message_is_none() {
        assert!(
            PolicyResolution::Absent.malformed_message().is_none(),
            "Absent must not produce a malformed message"
        );
    }

    #[test]
    fn loaded_malformed_message_is_none() {
        let resolution = PolicyResolution::Loaded(Policy::default());
        assert!(
            resolution.malformed_message().is_none(),
            "Loaded must not produce a malformed message"
        );
    }

    #[test]
    fn malformed_message_contains_path_and_error() {
        let msg = malformed("/cfg/policy.toml", "expected key at line 1")
            .malformed_message()
            .expect("Malformed must produce a message");
        assert!(
            msg.contains("/cfg/policy.toml"),
            "message must name the file: {msg}"
        );
        assert!(
            msg.contains("expected key at line 1"),
            "message must include the error: {msg}"
        );
    }

    #[test]
    fn absent_status_is_none() {
        assert!(
            PolicyResolution::Absent.status().is_none(),
            "Absent must not produce a PolicyStatus"
        );
    }

    #[test]
    fn loaded_status_is_none() {
        assert!(
            PolicyResolution::Loaded(Policy::default())
                .status()
                .is_none(),
            "Loaded must not produce a PolicyStatus"
        );
    }

    #[test]
    fn malformed_status_has_correct_fields() {
        let status = malformed("/cfg/policy.toml", "bad toml")
            .status()
            .expect("Malformed must produce a PolicyStatus");
        assert_eq!(
            status.state, POLICY_STATE_MALFORMED,
            "state must be the canonical malformed string"
        );
        assert_eq!(status.path, "/cfg/policy.toml");
        assert_eq!(status.error, "bad toml");
    }

    #[test]
    fn policy_status_roundtrips_json() {
        // PolicyStatus is serialized into daemon.status; confirm it survives a
        // JSON round-trip with all fields intact (issue #350).
        let original = PolicyStatus {
            state: POLICY_STATE_MALFORMED.to_string(),
            path: "/home/user/.config/mx-agent/policy.toml".to_string(),
            error: "failed to parse policy: expected value at line 3 col 1".to_string(),
        };
        let json = serde_json::to_string(&original).expect("PolicyStatus must serialize");
        let roundtrip: PolicyStatus =
            serde_json::from_str(&json).expect("PolicyStatus must deserialize");
        assert_eq!(original, roundtrip);
        // Keys must be present in the JSON for backward-compatible consumers.
        assert!(json.contains("\"state\""), "json: {json}");
        assert!(json.contains("\"path\""), "json: {json}");
        assert!(json.contains("\"error\""), "json: {json}");
        assert!(json.contains(POLICY_STATE_MALFORMED), "json: {json}");
    }

    // ── resolve_policy() integration tests via MX_AGENT_CONFIG_DIR ──────────
    //
    // These tests mutate the process-global `MX_AGENT_CONFIG_DIR` environment
    // variable. They use the shared crate-level lock
    // (`crate::tests::config_dir_env_lock`) so they are serialized against every
    // other module (including `scheduler_loop`) that modifies the same variable.

    struct PolicyEnvGuard {
        dir: std::path::PathBuf,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl PolicyEnvGuard {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static CTR: AtomicU64 = AtomicU64::new(0);
            let n = CTR.fetch_add(1, Ordering::Relaxed);
            let lock = crate::tests::config_dir_env_lock();
            let dir = std::env::temp_dir().join(format!(
                "mx-agent-policy-resolve-{}-{}-{}",
                label,
                std::process::id(),
                n
            ));
            std::env::set_var(mx_agent_policy::ENV_CONFIG_DIR, &dir);
            Self { dir, _lock: lock }
        }
    }

    impl Drop for PolicyEnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(mx_agent_policy::ENV_CONFIG_DIR);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn resolve_policy_missing_file_returns_absent() {
        // Config dir exists but no policy.toml → Absent (silent deny-all default).
        let guard = PolicyEnvGuard::new("absent");
        // Do NOT create the dir or file so neither exists.
        let resolution = resolve_policy();
        drop(guard);
        assert!(
            matches!(resolution, PolicyResolution::Absent),
            "missing policy file must resolve to Absent"
        );
    }

    #[test]
    fn resolve_policy_malformed_toml_returns_malformed() {
        // A present file with broken TOML must resolve to Malformed, not Absent.
        // This is the key invariant of issue #350: fail loudly, not silently.
        let guard = PolicyEnvGuard::new("malformed");
        std::fs::create_dir_all(&guard.dir).unwrap();
        std::fs::write(guard.dir.join("policy.toml"), "not valid toml !! [[[").unwrap();
        let resolution = resolve_policy();
        drop(guard);
        match resolution {
            PolicyResolution::Malformed { display, .. } => {
                assert!(
                    !display.is_empty(),
                    "Malformed resolution must carry a diagnostic message"
                );
            }
            other => panic!("malformed policy.toml must resolve to Malformed, got {other:?}"),
        }
    }

    #[test]
    fn resolve_policy_invalid_policy_returns_malformed() {
        // Syntactically valid TOML with a semantic error must also be Malformed.
        let guard = PolicyEnvGuard::new("invalid");
        std::fs::create_dir_all(&guard.dir).unwrap();
        std::fs::write(
            guard.dir.join("policy.toml"),
            "[rooms.\"not-a-room\"]\ntrusted = true\n",
        )
        .unwrap();
        let resolution = resolve_policy();
        drop(guard);
        assert!(
            matches!(resolution, PolicyResolution::Malformed { .. }),
            "semantically invalid policy must resolve to Malformed"
        );
    }

    #[test]
    fn resolve_policy_valid_file_returns_loaded() {
        // A present, well-formed file must resolve to Loaded.
        let guard = PolicyEnvGuard::new("valid");
        std::fs::create_dir_all(&guard.dir).unwrap();
        std::fs::write(
            guard.dir.join("policy.toml"),
            "[execution]\nnetwork = \"deny\"\n",
        )
        .unwrap();
        let resolution = resolve_policy();
        drop(guard);
        assert!(
            matches!(resolution, PolicyResolution::Loaded(_)),
            "valid policy file must resolve to Loaded"
        );
    }

    #[test]
    fn resolve_policy_for_enforcement_on_malformed_returns_deny_all() {
        // When the policy is malformed, resolve_policy_for_enforcement must never
        // panic or error — it must return the empty deny-all default (fail-closed).
        let guard = PolicyEnvGuard::new("enforce-malformed");
        std::fs::create_dir_all(&guard.dir).unwrap();
        std::fs::write(guard.dir.join("policy.toml"), "not valid toml !! [[[").unwrap();
        let policy = resolve_policy_for_enforcement("test.malformed");
        drop(guard);
        assert!(
            policy.rooms.is_empty(),
            "malformed policy must authorize nothing (deny-all default, no rooms)"
        );
    }

    #[test]
    fn absent_and_malformed_both_deny_all_but_differ_in_message() {
        // Issue #350 core invariant: both absent and malformed fall back to the
        // same deny-all policy, but only malformed produces a diagnostic message.
        // This ensures the two states remain distinguishable at the call-site level.
        let absent_msg = PolicyResolution::Absent.malformed_message();
        let malformed_msg = malformed("/path/policy.toml", "parse error").malformed_message();

        assert!(
            absent_msg.is_none(),
            "Absent must have no malformed message"
        );
        assert!(
            malformed_msg.is_some(),
            "Malformed must have a malformed message"
        );

        // Both produce the deny-all default policy.
        assert!(PolicyResolution::Absent.into_policy().rooms.is_empty());
        assert!(malformed("/path/policy.toml", "parse error")
            .into_policy()
            .rooms
            .is_empty());
    }
}
