//! Daemon-local in-flight invocation counter (issue #312).
//!
//! `AgentLoad.running_invocations` advertises how many invocations an agent is
//! currently running. Before this module it was a registration-time placeholder
//! (always `0`) carried forward by every heartbeat, so `agent show` reported a
//! permanently-idle `0/N` load regardless of real work.
//!
//! This module maintains a process-wide, in-memory count of running invocations
//! per executing `agent_id`, incremented when a remote `exec`/`call` starts and
//! decremented when it finishes, is cancelled, is rejected, or errors. The
//! heartbeat loop reads it via [`running_invocations`] and publishes the live
//! value (see [`crate::heartbeat::emit_heartbeat`]).
//!
//! The count is **in-memory only and never persisted**: a daemon restart kills
//! every live invocation, so resetting to `0` on restart is correct (mirrors the
//! live-exec control registry in [`crate::exec`]). It is purely advisory — load
//! is a display signal and is never an authorization input.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Process-wide map of executing `agent_id` → number of invocations currently
/// running on this daemon. Entries are removed when their count reaches `0` so
/// the map stays bounded by the number of *concurrently active* agents.
static INFLIGHT: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();

fn inflight() -> &'static Mutex<HashMap<String, u32>> {
    INFLIGHT.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Number of invocations currently running for `agent_id` on this daemon.
///
/// Returns `0` for an agent with no in-flight work (the common, idle case). The
/// count is in-memory only and resets to `0` on daemon restart.
pub(crate) fn running_invocations(agent_id: &str) -> u32 {
    inflight()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(agent_id)
        .copied()
        .unwrap_or(0)
}

/// RAII guard that counts one running invocation for an executing `agent_id`.
///
/// Constructing the guard with [`InflightGuard::enter`] increments the in-flight
/// count for the agent; dropping it decrements the count. Because the decrement
/// is tied to `Drop`, the count is released on **every** terminal path —
/// finished, cancelled, rejected, errored, or panicked — without per-path
/// bookkeeping. To cover an invocation's whole lifetime, the guard must be moved
/// into the task that runs it (not held on a synchronous setup path, where it
/// would drop immediately).
///
/// Counting uses saturating arithmetic and tolerates a poisoned lock, so it can
/// never panic the daemon.
#[must_use = "the in-flight count is only held while the guard is alive; drop it too early and the count is wrong"]
pub struct InflightGuard {
    agent_id: String,
}

impl InflightGuard {
    /// Increment the in-flight count for `agent_id` and return a guard that
    /// decrements it on drop.
    pub fn enter(agent_id: &str) -> Self {
        let mut map = inflight().lock().unwrap_or_else(|e| e.into_inner());
        let count = map.entry(agent_id.to_string()).or_insert(0);
        *count = count.saturating_add(1);
        Self {
            agent_id: agent_id.to_string(),
        }
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        let mut map = inflight().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.agent_id) {
            *count = count.saturating_sub(1);
            // Remove the entry at zero so the map stays bounded by the number of
            // concurrently active agents rather than every agent ever seen.
            if *count == 0 {
                map.remove(&self.agent_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The counter is process-global, so tests use distinct agent ids to stay
    // independent of each other and of any concurrently running test.
    #[test]
    fn enter_increments_and_drop_decrements() {
        let agent = "inflight-test-basic";
        assert_eq!(running_invocations(agent), 0);
        {
            let _guard = InflightGuard::enter(agent);
            assert_eq!(running_invocations(agent), 1);
        }
        // Dropping the guard releases the count and removes the entry.
        assert_eq!(running_invocations(agent), 0);
    }

    #[test]
    fn overlapping_guards_for_same_agent_stack() {
        let agent = "inflight-test-overlap";
        let g1 = InflightGuard::enter(agent);
        let g2 = InflightGuard::enter(agent);
        assert_eq!(running_invocations(agent), 2);
        drop(g1);
        assert_eq!(running_invocations(agent), 1, "one of two still running");
        drop(g2);
        assert_eq!(running_invocations(agent), 0, "both finished");
    }

    #[test]
    fn distinct_agents_are_counted_separately() {
        let a = "inflight-test-a";
        let b = "inflight-test-b";
        let _ga = InflightGuard::enter(a);
        assert_eq!(running_invocations(a), 1);
        assert_eq!(running_invocations(b), 0);
    }

    #[test]
    fn count_returns_to_zero_across_start_finish_cancel_reject() {
        // Each terminal path is modelled by the guard simply dropping; the count
        // returns to 0 every time regardless of *why* the invocation ended.
        let agent = "inflight-test-terminal";
        for _ in 0..3 {
            let guard = InflightGuard::enter(agent);
            assert_eq!(running_invocations(agent), 1);
            drop(guard); // finish / cancel / reject all decrement the same way
            assert_eq!(running_invocations(agent), 0);
        }
    }
}
