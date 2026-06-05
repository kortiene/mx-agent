# Signed Task Action Authorization

## Problem Statement

Structured task actions can trigger execution in the daemon scheduler. Local policy alone is insufficient because `TaskState.created_by` and task state fields are advisory Matrix state. The daemon must require a trusted, signed privileged request before treating a task action as executable.

## Goals

- Keep room task state advisory unless an action carries a signed authorization.
- Require Ed25519 signature verification for executable task actions.
- Require the signing key to be trusted in the local trust store; revoked keys must deny execution.
- Apply nonce/expiry replay protection before policy/claim/dispatch.
- Ensure unsigned/untrusted/revoked/replayed/expired task actions do not execute.

## Non-Goals

- Do not create a new Matrix event type in this issue.
- Do not alter Matrix device trust or E2EE behavior.
- Do not remove local policy checks from #165.
- Do not add live Matrix e2e tests; use deterministic scheduler/protocol tests.

## Relevant Repository Context

- Protocol signing helpers already sign/verify canonical JSON with the `signature` field excluded.
- `TaskAction` is embedded in `TaskState.action`.
- `TaskOrchestrator` now supports local policy and audit before claim/dispatch.
- `TrustStore` is the local final authority for `(agent_id, key_id)` trust records.
- `ReplayCache` enforces nonce/expiry for privileged requests.

## Proposed Implementation

1. Add an optional `authorization` field to `TaskAction::Tool` and `TaskAction::Exec`.
2. Define `TaskActionAuthorization` with:
   - `requesting_agent`
   - `target_agent`
   - `created_at`
   - `expires_at`
   - `nonce`
   - `signature`
3. Add `TaskAction::authorization()` helper.
4. Add daemon authorization hooks to `TaskOrchestrator`:
   - optional `TrustStore`
   - optional mutable `ReplayCache`
5. Before local policy/claim/dispatch, require authorization when trust/replay checking is configured. If missing, invalid, untrusted, revoked, expired, or replayed, block the task with a stable result reason and do not dispatch.
6. Verify signature over a canonical JSON payload containing the task id, action payload with authorization removed, and authorization metadata with signature removed. This binds the approval to the specific task and action.
7. Use local trust store final authority keyed by `authorization.requesting_agent` and `signature.key_id`.
8. Maintain #165 local policy checks after signature/trust/replay acceptance.

## Affected Files / Crates / Modules

- `crates/mx-agent-protocol/src/schema.rs`
- `crates/mx-agent-daemon/src/task_orchestrator.rs`
- `crates/mx-agent-daemon/src/lib.rs`
- `docs/architecture.md`

## CLI / API Changes

- Public protocol API gains `TaskActionAuthorization` and helper methods.
- Public daemon API gains `TaskOrchestrator` trust/replay builder methods.
- No CLI surface changes.

## Data Model / Protocol Changes

- Additive optional `authorization` field under task actions.
- Existing tasks without authorization remain valid but advisory/non-executable when trust/replay enforcement is configured.

## Security Considerations

- Missing authorization must fail closed when trust/replay enforcement is configured.
- Local trust store is final authority; revoked keys fail.
- Replay cache denial must be side-effect safe for expired/replayed requests.
- Authorization verification must happen before policy, claim, and dispatch.
- Do not log signatures, private keys, or secrets.

## Testing Plan

- Protocol serde tests for authorized tool/exec actions.
- Daemon unit tests for unsigned, untrusted, revoked, expired, replayed, and tampered actions denying before dispatch.
- Daemon unit test for trusted signed action proceeding through policy/dispatch.
- Verify denial result/audit shape remains non-sensitive.

## Documentation Updates

- Update architecture task-action section to document advisory vs signed executable actions.

## Risks and Open Questions

- This implements signed authorization embedded in task state as the selected option. A future issue may move this to a separate timeline event if needed.
- The scheduler core stores a mutable replay cache in memory for deterministic tests; live integration can wire it to persisted daemon state later.

## Implementation Checklist

- [ ] Add protocol authorization type and helpers.
- [ ] Add canonical task-action authorization payload helper.
- [ ] Add orchestrator trust/replay configuration.
- [ ] Enforce signature/trust/replay before policy/claim/dispatch.
- [ ] Add focused tests.
- [ ] Update architecture docs.
- [ ] Run required checks.
