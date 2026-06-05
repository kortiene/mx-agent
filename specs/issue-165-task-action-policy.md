# Enforce Local Policy for Task Actions

## Problem Statement

A Matrix room member can create task state with a structured action. Assignment must not imply execution permission: the daemon must apply its local deny-by-default policy before claiming or dispatching task actions, otherwise task state could become an execution trigger.

## Goals

- Evaluate local policy for task actions before claiming or executing them.
- Use existing policy rules for tool actions and raw exec actions.
- Audit policy denials.
- Ensure denied tasks do not spawn and are moved to a safe non-runnable state with a stable reason.
- Add tests covering malicious task action denial.

## Non-Goals

- Do not implement signed/trusted task requests; that is handled by #166.
- Do not expand the policy file format unless required; reuse existing room/agent/tool/exec/cwd rules.
- Do not add live Matrix or Docker e2e tests.

## Relevant Repository Context

- `mx-agent-policy` already provides `Policy::evaluate_call` and `Policy::evaluate_exec`.
- `mx-agent-daemon::task_orchestrator` is a pure scheduler core and currently claims before dispatcher policy errors can be returned.
- `mx-agent-daemon::audit` has `AuditRecord::for_call` and `AuditRecord::for_exec` plus `AuditLog`.
- `TaskState.created_by` is the best available requester identity for policy checks in this issue; `assigned_to` must still match the local orchestrator agent before policy is considered.

## Proposed Implementation

1. Add optional local policy configuration to `TaskOrchestrator` via builder methods, preserving `TaskOrchestrator::new` for existing tests.
2. Map task actions to existing policy contexts:
   - `TaskAction::Tool` -> `Policy::evaluate_call` using room id and `task.created_by`.
   - `TaskAction::Exec` -> `Policy::evaluate_exec` using room id, `task.created_by`, command, and cwd.
3. If no policy is configured in the pure orchestrator core, keep existing test/default behavior. When policy is configured, deny-by-default policy results must be honored.
4. Perform the policy check after action parsing/dependency checks but before claim/update/dispatch.
5. On denial:
   - append an audit record (tool or exec, redacted by existing audit helpers);
   - do not call `claim` or `dispatch`;
   - move the task to `blocked` with a stable task result (`reason=policy_denied`, summary from deny reason);
   - return `OrchestrationOutcome::Denied`.
6. On allow: optionally audit the allowed decision, then proceed to claim/dispatch as before.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/task_orchestrator.rs`
- `crates/mx-agent-daemon/src/lib.rs`
- `docs/architecture.md`

## CLI / API Changes

- Public daemon API: `TaskOrchestrator` builder methods for room, policy, and audit log.
- No CLI command surface changes.

## Data Model / Protocol Changes

None. Denial results use the stable result schema from #164 and existing task states.

## Security Considerations

- Denied actions must not claim, dispatch, or spawn.
- Policy is local and deny-by-default.
- Audit logs must use existing redaction for exec argv.
- This does not establish task requester authenticity; #166 adds trust/signature checks.

## Testing Plan

- Unit tests for tool policy denial: no claim, no dispatch, task becomes blocked, result reason is `policy_denied`, audit log line is written.
- Unit tests for exec policy denial using disallowed command/cwd.
- Unit test for allowed policy proceeding to dispatch.
- Verify existing dispatch denial behavior still works.

## Documentation Updates

- Update architecture task orchestration text to state local policy is checked before claim/dispatch and denials are audited.

## Risks and Open Questions

- `TaskState.created_by` is not authenticated by itself; this issue only enforces local policy against the available requester field. #166 must require trusted signatures before execution.
- If audit append fails, the orchestrator should fail closed without dispatching.

## Implementation Checklist

- [ ] Add policy/audit fields and builder methods to `TaskOrchestrator`.
- [ ] Add action-to-policy evaluation and audit helpers.
- [ ] Check policy before claim/dispatch.
- [ ] Block denied tasks with stable result.
- [ ] Add focused tests.
- [ ] Run required checks.
