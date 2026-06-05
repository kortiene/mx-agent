# Stable Task Result Schema

## Problem Statement

`TaskState.result` is currently arbitrary JSON. Automation can read the full task JSON, but it cannot reliably distinguish success, process failures, denials, or recovery outcomes without knowing daemon-internal ad hoc object shapes.

## Goals

- Add a documented stable result object shape for `com.mxagent.task.v1` results.
- Keep `TaskState.result` backward compatible as optional JSON so older or future result extensions still round-trip.
- Make daemon task orchestration write stable result objects for completed, failed, denied, and recovered tasks.
- Make CLI human output display useful result summaries while `--json` continues to include the full result object.

## Non-Goals

- Do not change task event type names or bump schema version.
- Do not remove forward compatibility for arbitrary result JSON already present in room state.
- Do not change signing, trust, policy, or process execution semantics.

## Relevant Repository Context

- `mx-agent-protocol::schema::TaskState.result` is `Option<Value>`.
- `mx-agent-daemon::task_orchestrator` writes current result JSON via ad hoc `success_result` and inline `json!` objects.
- `mx-agent-cli::print_task` renders task metadata for human output and `--json` serializes the full `TaskState`.

## Proposed Implementation

1. Add a documented `TaskResult` protocol struct with stable fields:
   - `status`
   - `completed_by`
   - `completed_at`
   - `invocation_id`
   - `action`
   - `reason`
   - `exit_code`
   - `summary`
   - `artifact_mxc`
2. Keep `TaskState.result: Option<Value>` for backward compatibility.
3. Add `TaskResult::to_value()` or equivalent helper for daemon writes.
4. Update orchestrator result generation:
   - `succeeded`: `status=succeeded`, no reason, exit code/summary/artifact from dispatcher.
   - process/action failure: `status=failed`, `reason=process_exit` or `dispatch_failed`.
   - policy denial: `status=failed`, `reason=policy_denied`.
   - recovery: `status=failed`, `reason=recovered_stale_invocation`.
5. Include `completed_by` from the orchestrator's local agent id and `completed_at` as an RFC3339 timestamp.
6. Update CLI `print_task` to display result status, reason, exit code, and summary when present.

## Affected Files / Crates / Modules

- `crates/mx-agent-protocol/src/schema.rs`
- `crates/mx-agent-daemon/src/task_orchestrator.rs`
- `crates/mx-agent-cli/src/cli.rs`
- `docs/architecture.md`

## CLI / API Changes

- New public `TaskResult` protocol type.
- Human task output includes a result summary when `TaskState.result` has stable fields.
- JSON output remains unchanged except daemon-written result objects now use stable fields.

## Data Model / Protocol Changes

- Additive stable schema for the existing `result` field; no event type/version change.
- `TaskState.result` remains optional and backward compatible.

## Security Considerations

- Result summaries must be non-sensitive; do not include raw command output or secrets.
- Policy denials are represented as results but do not imply execution occurred.
- No changes to signing, trust, or deny-by-default policy enforcement.

## Testing Plan

- Protocol serde tests for `TaskResult` examples.
- Orchestrator tests asserting stable result fields for success, process failure, policy denial, and recovery.
- CLI unit test for result summary extraction/rendering helper.

## Documentation Updates

- Document the stable `result` object under architecture §9.2.

## Risks and Open Questions

- Existing arbitrary `result` values remain valid but may not render all summary fields in the CLI.
- `completed_at` is generated at orchestration time and should be asserted by shape rather than exact value in tests.

## Implementation Checklist

- [ ] Add `TaskResult` protocol type and tests.
- [ ] Update orchestrator result generation.
- [ ] Update CLI human result summary.
- [ ] Update architecture docs.
- [ ] Run required checks.
