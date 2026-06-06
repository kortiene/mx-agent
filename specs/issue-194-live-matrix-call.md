# Issue #194 — Live Matrix-backed remote call

## Goal

Implement `mx-agent call --room <room> --agent <agent>` as a daemon-mediated live Matrix request/response flow. Local calls without a room/agent keep the loopback behavior from #193.

## Design

### Agent signing-key discovery

Remote signature verification requires the target daemon to resolve the requester's Ed25519 verifying key. A `key_id` is only a SHA-256 digest of the public key, so the public key cannot be recovered from it. This change makes the binding explicit and additive:

- `AgentState.signing_key_id` is populated at registration.
- `AgentState.signing_public_key` is added as optional base64-no-pad Ed25519 public key bytes.
- The target reads the requester's `com.mxagent.agent.v1` state, decodes `signing_public_key`, verifies that its digest matches both the published and request signature `key_id`, then passes the resulting `VerifyingKey` into `authorize_call_request`.
- The local `TrustStore` remains the authority: valid signatures from unknown/revoked keys are rejected.

### Call request targeting

`CallRequest` gets optional `requesting_agent` and `target_agent` fields. They are included in the signed payload when live calls are sent. The sync loop only executes a call when `target_agent` names an agent state in the room owned by the local Matrix user.

### Requester flow

`call.start` chooses live Matrix mode only when both `room` and `agent` are present:

1. Restore daemon Matrix session.
2. Resolve room and requester agent id from local agent state.
3. Sign and send `com.mxagent.call.request.v1`.
4. Sync with a bounded timeout until the matching `com.mxagent.call.response.v1` arrives.
5. Return the existing `CallStartResult`/`CallOutcome` shape to the CLI.

### Target flow

The daemon `/sync` router dispatches `call.request`; the live handler:

1. Requires `target_agent` and confirms it is local.
2. Resolves requester agent state and verifying key.
3. Loads trust and policy (missing policy means deny-by-default).
4. Runs `authorize_call_request`.
5. Executes the authorized built-in tool and emits `call.response`; rejections emit `ok:false` with a stable reason.

## Security notes

- CLI remains stateless and never executes tools.
- Raw tool input is not logged.
- Execution only occurs after signature verification, local trust, local policy, and target-agent matching.
- Public-key publication is non-secret and is bound to `key_id` by digest checks.

## Tests

- Unit tests for public-key encoding/resolution, target filtering, untrusted key/policy rejection using existing authorization tests.
- Matrix integration harness extended for a gated two-user live call happy path when Docker Matrix is available.
