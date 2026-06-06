# Issue 226 README Status Corrections

## Problem Statement

The public alpha README and alpha release checklist contain status/security statements that lag the current binary. They understate shipped sandbox, E2EE-decryption, and artifact behavior, while overstating nonce/expiry replay protection for `call.request`.

## Goals

- Correct the README project status table so sandbox, E2EE decryption, artifacts, and remaining planned work match the implementation.
- Correct README security posture wording so it does not claim all privileged request kinds have nonce/expiry replay protection.
- Update alpha checklist known limitations so its documentation gate reflects the same candidate-binary reality.
- Preserve the security framing: sandboxing is helpful but not a standalone security boundary; `none` remains the default fallback.

## Non-Goals

- Do not implement new sandbox, E2EE, artifact, or `call` nonce behavior.
- Do not broaden CLI or daemon behavior.
- Do not update the unrelated `lint` tool issue unless nearby documentation in scope directly advertises it.

## Relevant Repository Context

- `README.md` is the primary public status source.
- `docs/alpha-release-checklist.md` is the release gate and includes known limitations that must match reality.
- `crates/mx-agent-sandbox/src/lib.rs` implements `none`, `bubblewrap`, and container backends, while documenting missing seccomp/rlimit/UID-GID remap controls.
- `crates/mx-agent-daemon/src/artifact.rs` implements stream artifact mode with Matrix media upload, SHA-256 digest, optional zstd, and tail previews.
- Matrix integration coverage exercises E2EE privileged-event decryption and fail-safe behavior.

## Proposed Implementation

- Edit only documentation unless context inspection reveals another stale status sentence in the same surfaces.
- In `README.md`:
  - Split or rewrite the status rows so implemented sandbox backends are accurately described.
  - Clarify E2EE decryption/UTD safety ships today, while production hardening UX remains planned.
  - Clarify large-output artifact mode ships, while very-large-output tuning remains planned.
  - Keep interactive PTY and tight task↔remote-invocation id unification as planned.
  - Reword security posture from universal signature+nonce+expiry to signature+local policy for all privileged requests, with nonce/expiry where the schema provides them.
- In `docs/alpha-release-checklist.md`:
  - Replace the combined “Large output artifacts and production E2EE are still landing” limitation with precise shipped/planned boundaries.
  - Ensure sandbox limitation says backends exist/selectable but are not a standalone boundary.

## Affected Files / Crates / Modules

- `README.md`
- `docs/alpha-release-checklist.md`
- `docs/security-hardening.md`
- `wiki/AI-Agent-Orchestration.md`
- `wiki/Security-and-Sandboxing.md`
- `wiki/Stream-and-Protocol-Spec.md`

## CLI / API Changes

None.

## Data Model / Protocol Changes

None.

## Security Considerations

This is documentation-only, but security-sensitive because users rely on these status statements. Avoid overstating protection for `call.request`; keep the deny-by-default policy, signature verification, and sandbox limitations explicit. Do not expose or add secrets.

## Testing Plan

- Run `cargo fmt --check` to ensure repository formatting is unaffected.
- Run `cargo test --all` as the relevant default gate for a docs-only change.
- If time permits, run the remaining standard checks required by the issue workflow (`cargo build --all`, clippy).

## Documentation Updates

This spec itself plus README, alpha checklist, security-hardening, and directly contradictory wiki status wording corrections.

## Risks and Open Questions

- Wiki pages are mirrored to GitHub wiki and contain some status language; update only direct contradictions found during review to avoid leaving linked documentation stale.

## Implementation Checklist

- [x] Edit README project status and security posture.
- [x] Edit alpha checklist known limitations.
- [x] Update directly contradictory wiki/security-guide status statements found during review.
- [x] Review resulting docs for misleading claims about alpha behavior.
- [x] Run local checks.
- [ ] Commit, PR, and merge per `/issue` workflow.
