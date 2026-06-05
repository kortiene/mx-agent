# Structured Task Action Payloads

## Problem Statement

Tasks currently carry human-readable metadata and lifecycle state, but the durable `com.mxagent.task.v1` schema does not expose a first-class machine-readable action field. The daemon has a forward-compatible parser for `extra["action"]`, but producers and public protocol types should model the field directly so agents can create safe, explicit work without inferring behavior from titles or descriptions.

## Goals

- Add an optional structured `action` field to `TaskState`.
- Support tool actions and exec actions in the protocol model.
- Keep old tasks without `action` valid and non-auto-executable.
- Keep JSON serialization backward compatible by omitting `action` when absent.
- Let `task create` and `task update` set or replace action metadata using CLI flags.
- Preserve existing orchestrator behavior while preferring the typed field.

## Non-Goals

- Do not implement automatic execution of all task actions beyond existing orchestrator core behavior.
- Do not change Matrix event type names or bump protocol version.
- Do not alter authorization, signing, or policy enforcement paths.
- Do not add live Matrix/Docker e2e tests.

## Relevant Repository Context

- `mx-agent-protocol::schema::TaskState` models `com.mxagent.task.v1` and uses `extra` for forward compatibility.
- `mx-agent-daemon::task` builds and updates `TaskState` for Matrix room state.
- `mx-agent-daemon::task_orchestrator` already defines a `TaskAction` enum and parses `extra["action"]` before dispatching through a signed/policy-checked abstraction.
- `mx-agent-cli` task commands build `CreateTaskOptions` and `UpdateTaskOptions` and send them over stateless IPC.
- The CLI already has `parse_tool_args` and `--input-json` patterns for named tool calls.

## Proposed Implementation

1. Move or duplicate the public action model into `mx-agent-protocol::schema` as documented `TaskAction` with serde tag `type` and variants:
   - `Tool { tool, args }`
   - `Exec { command, cwd, env, timeout_ms, stream }`
2. Add `TaskState.action: Option<TaskAction>` with `#[serde(default, skip_serializing_if = "Option::is_none")]` before `extra`.
3. Update daemon `CreateTaskOptions` and `UpdateTaskOptions` with optional `action`.
4. Update task construction/update application to set the typed field.
5. Update orchestrator to use `task.action` first, then fall back to `extra["action"]` for already-published forward-compatible tasks.
6. Add CLI task flags:
   - tool: `--tool TOOL`, repeated `--arg KEY=VALUE`, `--input-json FILE`
   - exec: `--exec`, `--cwd PATH`, `--timeout-ms MS`, `--stream`, trailing `-- COMMAND ...`
   - update can use the same flags to replace the task action.
7. Reject conflicting/incomplete action flag combinations locally with human-readable errors.

## Affected Files / Crates / Modules

- `crates/mx-agent-protocol/src/schema.rs`
- `crates/mx-agent-daemon/src/task.rs`
- `crates/mx-agent-daemon/src/task_orchestrator.rs`
- `crates/mx-agent-daemon/src/lib.rs`
- `crates/mx-agent-cli/src/cli.rs`
- `docs/architecture.md` if examples need alignment

## CLI / API Changes

- Public API: `TaskState.action`, `TaskAction`, `CreateTaskOptions.action`, `UpdateTaskOptions.action`.
- CLI: `mx-agent task create/update` can set action metadata with tool or exec flags.
- IPC payloads gain optional `action` fields through existing serde options.

## Data Model / Protocol Changes

- Additive `action` field to `com.mxagent.task.v1` content.
- No version bump; old content without `action` still deserializes and serializes without a new field.
- Readers should still tolerate old action values stored in `extra`.

## Security Considerations

- Action metadata is descriptive only; it must not bypass signing, trust, or deny-by-default policy.
- CLI remains stateless and only sends action metadata to the daemon.
- Do not log secrets or accept secret-bearing fixtures.
- Exec actions are not permission grants; orchestrator/dispatcher must continue to enforce policy before spawning.
- Unix-only path assumptions are preserved.

## Testing Plan

- Protocol serde tests for old tasks without action, tool action tasks, and exec action tasks.
- Daemon task unit tests for create/update preserving and replacing action.
- Orchestrator tests for typed action and legacy `extra["action"]` fallback.
- CLI parser/helper tests for tool and exec action flags and conflict errors.

## Documentation Updates

- Align `docs/architecture.md` examples with the chosen `TaskAction` field names if needed.

## Risks and Open Questions

- `action` may also appear in `extra` from older producers; typed `TaskState.action` should take precedence.
- `--input-json` and repeated `--arg` should remain mutually exclusive for deterministic tool payloads.

## Implementation Checklist

- [ ] Add documented `TaskAction` to protocol schema.
- [ ] Add optional `TaskState.action` and protocol tests.
- [ ] Update daemon task options/build/update logic and tests.
- [ ] Update orchestrator imports/parser/tests.
- [ ] Add CLI action flags and builder validation tests.
- [ ] Run required cargo checks.
