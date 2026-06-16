//! Local authorization policy engine for mx-agent.
//!
//! This crate will evaluate whether a remote `exec`/`call` request is allowed
//! based on the policy file described in `docs/architecture.md`, section 13.3.
//! For now it exposes the default decision used before any policy is loaded.

mod engine;
mod file;

pub use engine::{Allowance, CallContext, DenyReason, ExecContext, Outcome};
pub use file::{
    AgentPolicy, ExecutionPolicy, NetworkPolicy, Policy, PolicyError, RawExecDefault, RoomPolicy,
    Sandbox, Seccomp, ENV_CONFIG_DIR, POLICY_FILE_NAME,
};

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request is permitted.
    Allow,
    /// The request is denied.
    Deny,
}

/// Default decision when no policy explicitly permits a request.
///
/// mx-agent is deny-by-default: anything not explicitly allowed is rejected.
pub fn default_decision() -> Decision {
    Decision::Deny
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_deny() {
        assert_eq!(default_decision(), Decision::Deny);
    }
}
