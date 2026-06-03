//! Process sandboxing backends for mx-agent remote execution.
//!
//! Backends (`none`, `bubblewrap`, container) are described in
//! `docs/architecture.md`, section 13.5. This crate currently only enumerates
//! the available backends and the default selection.

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

/// Default sandbox backend used until configured otherwise.
pub fn default_backend() -> Backend {
    Backend::None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_backend_is_none() {
        assert_eq!(default_backend(), Backend::None);
    }
}
