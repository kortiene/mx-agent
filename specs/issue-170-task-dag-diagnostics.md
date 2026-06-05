# Duplicate/Conflict Diagnostics for Task DAGs

## Problem Statement

A workspace room can contain duplicate task titles, dependency cycles, dangling dependency IDs, tasks assigned to unknown/inactive agents, runnable tasks with no action, or tool actions the assigned agent does not offer. These are valid Matrix state but confusing, and nothing surfaces them to the operator.

## Goals

- Compute non-blocking diagnostics over a room's tasks (and agents when available).
- Surface warnings in `task graph` (human output) and in `--json` as machine-readable diagnostics.
- Cover: duplicate titles, dependency cycles, missing dependency IDs, assigned-to-unknown-agent, assigned-to-inactive-agent, runnable-task-with-no-action, and tool-unavailable.
- Never block valid advanced workflows; diagnostics are warnings only.

## Non-Goals

- Do not reject or mutate task state based on diagnostics.
- Do not add a live Matrix/Docker e2e test.
- Do not change task lifecycle or execution behavior.

## Relevant Repository Context

- `mx-agent-daemon::task_graph::TaskGraph::from_tasks` already builds the DAG and detects cycles.
- `mx-agent-daemon::agent::list_agents_for_session` returns `Vec<AgentState>` (with `tools`, `capabilities`, `status`, `last_seen_ts`).
- `mx-agent-daemon::heartbeat::LivenessConfig` maps `last_seen_ts` to a `Liveness` verdict.
- `mx-agent-daemon::task_orchestrator::action_from_task` parses a task's action; `crate::task::is_runnable` classifies schedulable states.
- The daemon `task.graph` IPC handler has a Matrix session, so it can read both tasks and agents.

## Proposed Implementation

1. New `task_diagnostics` module with a documented `TaskDiagnostic { severity, kind, task_id, message }` and a pure `diagnose_tasks(tasks, agents) -> Vec<TaskDiagnostic>` (plus a deterministic `_at(now_ms)` variant for tests).
2. Checks:
   - `duplicate_title` — two or more tasks share a non-empty title.
   - `dependency_cycle` — from `TaskGraph::from_tasks(...).cycles`.
   - `missing_dependency` — a `depends_on` id is not a present task.
   - `assigned_to_unknown_agent` — assignee not among the room's agents (only when agents are provided).
   - `assigned_to_inactive_agent` — assignee exists but is stale/offline by liveness (only when agents are provided).
   - `runnable_without_action` — a `pending`/`assigned` task that is assigned but has no executable action.
   - `tool_unavailable` — a Tool action whose tool the assigned agent does not offer (only when agents are provided).
   - Agent-dependent checks are skipped when no agent data is available, so absence of agent state never produces misleading warnings.
3. Add an additive `warnings: Vec<TaskDiagnostic>` field to `TaskGraph` (empty from `from_tasks`).
4. The daemon `task.graph` handler reads tasks and agents and sets `graph.warnings = diagnose_tasks(&tasks, &agents)`.
5. CLI `task graph`: render a warnings section after the tree (human); `--json` serializes `warnings` automatically.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/task_diagnostics.rs` (new)
- `crates/mx-agent-daemon/src/task_graph.rs` (`warnings` field)
- `crates/mx-agent-daemon/src/lifecycle.rs` (`task.graph` handler)
- `crates/mx-agent-daemon/src/lib.rs` (exports)
- `crates/mx-agent-cli/src/cli.rs` (`task graph` rendering)
- `docs/architecture.md` (§9.5 note)

## CLI / API Changes

- New public daemon API: `TaskDiagnostic`, `diagnose_tasks`.
- `TaskGraph` gains a `warnings` field (additive; serialized in `--json`).
- `task graph` human output adds a warnings section.

## Data Model / Protocol Changes

None to Matrix event schemas. `TaskGraph` is an IPC/CLI result type; adding `warnings` is additive.

## Security Considerations

- Diagnostics are advisory; they never block or mutate tasks (no execution-permission implications).
- Messages are non-sensitive (task ids, titles, agent ids); no secrets logged.

## Testing Plan

- Unit tests for each diagnostic kind and for the "no agent data → skip agent checks" path, using the deterministic `_at` variant.
- Confirm `TaskGraph` still serializes (additive field).

## Documentation Updates

- Note the diagnostics in architecture §9.5.

## Implementation Checklist

- [ ] Add `task_diagnostics` module + tests.
- [ ] Add `TaskGraph.warnings`.
- [ ] Wire daemon `task.graph` handler to compute diagnostics with agents.
- [ ] Render warnings in CLI `task graph`.
- [ ] Export public types; update docs.
- [ ] Run required checks.
