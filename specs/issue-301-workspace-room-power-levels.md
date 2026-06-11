# Workspace rooms must provision power levels so non-creator daemons can write `com.mxagent.*` state

> GitHub issue #301 — `type:security area:daemon area:matrix area:security priority:p0`
> Found by the 2026-06-11 feature-completeness re-assessment at HEAD `a7680e8` (follow-up to epic #274).

## Problem Statement

The daemon creates workspace rooms through `build_create_room_request`
(`crates/mx-agent-daemon/src/workspace.rs:430-454`), which sets
name / topic / alias / visibility / preset and an optional `m.room.encryption`
initial-state event, but never sets `power_level_content_override`. Under Matrix
defaults the room creator gets power level (PL) 100, every joiner gets PL 0, and
state events require `state_default` = 50.

Every `com.mxagent.*.v1` **state** write the protocol depends on goes through
`room.send_state_event_raw` and therefore needs PL ≥ 50. So a *second* daemon
that joins a workspace receives `M_FORBIDDEN` on register / heartbeat /
task-claim / invocation-publish / trust-publish / workspace-attach — **multi-agent
workspaces are broken out of the box**, and no `mx-agent` command grants the
needed power. Failures surface as raw Matrix 403s with no guidance.

The integration suite hides the gap by manually granting power levels in **11
places** (`crates/mx-agent-daemon/tests/matrix_integration.rs`), encoding in test
setup exactly the provisioning production never performs.

The naive operator workaround — lowering `state_default` or broadly granting PLs
— is itself a state-integrity / DoS hazard: any room member could then overwrite
any agent's `com.mxagent.*` state. (Permissive PLs do **not** grant code
execution — the Ed25519 signature + local trust + deny-by-default policy gate
remains authoritative; see [Security Considerations](#security-considerations).)

The fix has three parts: (1) provision tight, per-event-type PLs at room
creation; (2) give the room creator a first-class, daemon-mediated way to grant a
joining daemon the "agent" PL; and (3) turn the raw 403 into a guided error that
tells the operator exactly how to obtain the missing power.

## Goals

- `build_create_room_request` emits a `power_level_content_override` with narrow
  per-event-type PLs for the six `com.mxagent.*` **state** types
  (`AGENT` / `TASK` / `INVOCATION` / `WORKSPACE` / `TRUST` / `TOOL`), so the PL
  model is explicit and never relies on a blanket `state_default` loosening.
- A non-creator daemon that has been granted the workspace "agent" PL can
  register, heartbeat, claim tasks, publish invocations, publish trust state, and
  attach — **with no manual test-side `m.room.power_levels` write**.
- A plain member who has *not* been granted the agent PL cannot overwrite another
  agent's `agent.v1` / `task.v1` / `invocation.v1` / `trust.v1` state (integrity /
  DoS protection at the PL layer, as defense-in-depth).
- A creator-only, daemon-mediated grant path exists to elevate a specific Matrix
  user to the agent PL (the production replacement for the 11 test-side grants).
- An `M_FORBIDDEN` from any of the six `send_state_event_raw` sites surfaces a
  guided, non-raw error naming the room, the event type, and the required PL, and
  pointing at the grant command — carrying **no** secrets.
- The 11 manual grants in `tests/matrix_integration.rs` are removed (or each
  justified), and the live suite passes against production-provisioned PLs.
- Documentation of the workspace PL model lands in `docs/architecture.md`,
  `docs/user-guide.md`, `docs/security-hardening.md`, and `docs/cli-reference.md`.

## Non-Goals

- No change to the Ed25519 signing / trust / policy / approval execution gate.
  Power levels are a Matrix transport/integrity property only; they never become
  a path to execution.
- No state-key-scoped authorization. Matrix PLs are a single integer per event
  *type* and cannot express "this user may only write the state key matching its
  own `agent_id`". Per-agent state-key isolation stays the job of the
  signature + trust layer; PLs only gate *whether* a member may write a given
  `com.mxagent.*` state type at all.
- No revoke/ungrant command in this change (a `workspace grant --level 0` form may
  cover it; a dedicated `workspace revoke` is a follow-up — see Open Questions).
- No auto-grant of every joiner. Membership ≠ agent role; elevation is an
  explicit creator decision.
- No change to timeline-event PLs beyond the Matrix default (`events_default` 0).
  Timeline events (`heartbeat`, `exec.request`, `call.request`, `stream.chunk`,
  `approval.*`, `pty.resize`) are signed and verified; any participant may emit
  them, exactly as today.
- No Windows support; no `unsafe`; no MSRV bump.

## Relevant Repository Context

**Crate ownership.** This is daemon + CLI + docs work. The owning crate is
`mx-agent-daemon` (Matrix room/state operations); `mx-agent-cli` gains one
subcommand; `mx-agent-protocol` is **unchanged** (PLs are a Matrix-room concept,
not an mx-agent event schema). The CLI stays stateless and never touches Matrix
credentials — the daemon performs all room/state writes (the documented
`auth login` carve-out does not apply here).

**Room creation (the one place to add the override).**
`build_create_room_request` (`crates/mx-agent-daemon/src/workspace.rs:430-454`)
is a *pure* helper (no homeserver round-trip) precisely so room-request
construction is unit-testable; it already injects the optional
`m.room.encryption` initial state the same way. `create_workspace`
(`workspace.rs:462-473`) calls it, then `client.create_room(request)`.

**The six state-write sites** (all `room.send_state_event_raw`, all needing PL ≥
50 under defaults):

| Site | File:line | State type | Notes |
|---|---|---|---|
| Agent register | `agent.rs:164` | `AGENT` | keyed by `agent_id` |
| Heartbeat republish | `heartbeat.rs:252` | `AGENT` | also emits a timeline `HEARTBEAT` via `send_raw` (PL 0 — fine) |
| Task publish/update | `task.rs:416` (`publish_task_state`) | `TASK` | keyed by `task_id` |
| Invocation lifecycle | `exec.rs:484` (`publish_invocation_state`) | `INVOCATION` | also reached via `invocation.rs:302`, `invocation.rs:379` |
| Trust-state mirror | `trust_state.rs:196` | `TRUST` | keyed by `trust_state_key(agent_id, key_id)` |
| Workspace attach | `workspace.rs:648` | `WORKSPACE` | empty state key |

`grep -rln send_state_event_raw crates/mx-agent-daemon/src` returns exactly these
six files. The `TOOL` state type has no live writer today but is part of the
state namespace (`mx_agent_protocol::events::state::ALL`) and is provisioned for
completeness/forward-compat.

**State-type constants** live in
`crates/mx-agent-protocol/src/events.rs:88-107`:
`state::{AGENT, TASK, INVOCATION, TOOL, WORKSPACE, TRUST}` and `state::ALL`.

**Error type.** `WorkspaceError` (`workspace.rs:215-296`) wraps
`matrix_sdk::Error` as `Matrix(Box<matrix_sdk::Error>)` with `Display`
"Matrix request failed: {e}". There is **no** existing Matrix error-kind
inspection in the daemon today (only `std::io::ErrorKind` matching elsewhere), so
detecting `M_FORBIDDEN` is new code.

**Join path.** `join_workspace` (`workspace.rs:507-517`) only calls
`client.join_room_by_id_or_alias`; it does nothing to power levels. The joining
daemon runs this and, at PL 0, **cannot** modify `m.room.power_levels` itself
(that requires the creator's PL) — which is why a self-grant-on-join is
infeasible and the grant must be creator-initiated (see Proposed Implementation).

**CLI / IPC wiring.** `WorkspaceCommand` (`crates/mx-agent-cli/src/cli.rs:263`)
has `Create` / `Join` / `Attach` / `Status`. IPC methods are dispatched in
`crates/mx-agent-daemon/src/lifecycle.rs:636-659` (`workspace.create`,
`workspace.join`, `workspace.attach`, `workspace.status`) and listed again around
`lifecycle.rs:1433`. Each daemon-side op uses the `*_for_session` wrappers
(`workspace.rs:479-503`) that `restore_client(session)` then call the core fn.

**Existing tests to mirror.** `build_create_room_request` already has six pure
unit tests at `workspace.rs:784-872` (e2ee on/off, private/public preset,
metadata passthrough, combined). New PL assertions go right beside them in the
same `mod tests`.

**Test-side grants to remove.** `crates/mx-agent-daemon/tests/matrix_integration.rs`
has 11 inline, identical grants (near lines 474, 721, 995, 1254, 1502, 2037,
2456, 2962, 3632, 4309, 4629). Each is a raw
`send_state_event_raw("m.room.power_levels", "", json!({...}))` that sets
`users_default:0, state_default:50, events_default:0,
users:{ <creator>:100, <joiner>:50 }, events:{ com.mxagent.agent.v1: 50 }`.
There is **no** shared helper today — the block is copy-pasted 11×, referencing
only the `AGENT` state type.

**matrix-sdk version.** `matrix-sdk 0.18` (`Cargo.toml:33`),
`ruma-client-api 0.24`. `create_room::v3::Request` exposes
`power_level_content_override: Option<Raw<RoomPowerLevelsEventContent>>`.
`matrix_sdk::Room` exposes `power_levels()` and `update_power_levels(...)` for
the grant read-modify-write. `Int` comes from `js_int` (already in tree).

**Docs.** Current PL guidance is only aspirational:
`docs/architecture.md:1182` ("Restrict task mutation by Matrix power levels…")
and `docs/architecture.md:1924` ("power levels restrict state-event mutation").
Nothing concrete in `cli-reference.md`, `user-guide.md`, or
`security-hardening.md`.

## Proposed Implementation

### 1. Provision per-event-type PLs at room creation (`workspace.rs`)

Add a `power_level_content_override` to `build_create_room_request`. Define a
single named constant for the agent role PL:

```rust
/// Power level a workspace member needs to publish any `com.mxagent.*` state
/// event (agent / task / invocation / trust / workspace / tool). The room
/// creator (PL 100) grants this to each participating daemon via
/// `workspace grant`; a plain member stays at PL 0 and is refused.
pub(crate) const WORKSPACE_AGENT_PL: i64 = 50;
```

Build the override so it sets **only** the `events` map (plus re-affirms the
defaults), and deliberately **omits the `users` map**:

- The `power_level_content_override` is overlaid on the homeserver's default
  power-levels content. Omitting `users` preserves the default
  `users: { <creator>: 100 }`, so the creator keeps PL 100 **without
  `build_create_room_request` needing to know the creator's Matrix ID** (keeping
  the function pure and unit-testable). Setting `users` here would *replace* the
  default map and could lock the creator out — do not set it.
- Set `events` to `{ AGENT: 50, TASK: 50, INVOCATION: 50, WORKSPACE: 50,
  TRUST: 50, TOOL: 50 }` (the `events` map gates both timeline and state events
  of that type; only state types are listed). Iterate
  `mx_agent_protocol::events::state::ALL` so the set can never drift from the
  protocol's state namespace.
- Re-affirm `users_default: 0`, `events_default: 0`. For `state_default`, choose
  between **50** (Matrix default; granted agents at PL 50 may also change native
  room state like name/topic) and **100** (only the creator may change native
  room state; tighter). **Recommendation: `state_default = 100`** — it locks
  native room metadata to the creator while the explicit `events` entries let
  granted agents (PL 50) write `com.mxagent.*` state. Flag as an Open Question.

Construct the content type-safely:

```rust
use matrix_sdk::ruma::events::room::power_levels::RoomPowerLevelsEventContent;
use matrix_sdk::ruma::{Int, events::{TimelineEventType}};

let mut pl = RoomPowerLevelsEventContent::new();
pl.users_default = Int::new(0).unwrap();
pl.events_default = Int::new(0).unwrap();
pl.state_default = Int::new(100).unwrap(); // creator-only native state (see Open Questions)
for ty in mx_agent_protocol::events::state::ALL {
    pl.events.insert(TimelineEventType::from(*ty), Int::new(WORKSPACE_AGENT_PL).unwrap());
}
request.power_level_content_override = Some(Raw::new(&pl).expect("static PL content"));
```

(If the exact `RoomPowerLevelsEventContent` field/`Int` ergonomics in
matrix-sdk 0.18 prove awkward, an equivalent and equally valid path is to build
the content as a `serde_json::Value` and wrap with `Raw::from_json` /
`to_raw_value` — the same raw-JSON shape the tests use today. Keep whichever the
unit test can introspect cleanly via `Raw::deserialize`/`get_field`.)

**Do not** alter the e2ee `initial_state` logic; the override is an additional
field on the same request.

### 2. Creator-only grant path (CLI + IPC + daemon)

A joiner at PL 0 cannot grant itself, so the elevation must be performed by the
room creator's daemon (which holds PL 100). Add an explicit, creator-run command:

```
mx-agent workspace grant --room <ID|#alias> --user <@mxid:server> [--level <N>]
```

- **CLI** (`mx-agent-cli/src/cli.rs`): add `Grant(WorkspaceGrantArgs)` to
  `WorkspaceCommand`, with `--room`, `--user`, optional `--level` (default
  `WORKSPACE_AGENT_PL` = 50), and the standard `--json` handling. Help text
  states this must be run by the workspace creator (or any member whose PL is
  high enough to edit `m.room.power_levels`). Dispatch it over IPC like the other
  workspace subcommands; the CLI never builds a Matrix client.
- **IPC** (`lifecycle.rs`): add a `workspace.grant` method that parses a new
  `GrantWorkspaceOptions { room: String, user: String, level: Option<i64> }`
  params struct and calls a new `grant_workspace_for_session`. Register it in the
  dispatch `match` (~`lifecycle.rs:636`) and in the method list (~`:1433`).
- **Daemon** (`workspace.rs`): add `grant_workspace(client, options)` →
  `grant_workspace_for_session(session, options)`. Implementation:
  1. Resolve the room (sync_once + `resolve_room_id` + `get_room`, mirroring
     `attach_workspace`).
  2. Parse `--user` into an `OwnedUserId`; invalid → `WorkspaceError::InvalidTarget`.
  3. Apply the elevation with `room.update_power_levels(vec![(&user_id,
     Int::new(level).…)])` (read-modify-write handled by the SDK), which writes
     an updated `m.room.power_levels`. Map an `M_FORBIDDEN` here (caller lacks PL
     100) to the same guided error (event type `m.room.power_levels`).
  4. Return a small non-secret summary (`{ room_id, user, level }`) for human /
     `--json` output.

This is the production replacement for the 11 test-side raw grants.

> Rejected alternative — grant on `join_workspace`/`attach`: the joining daemon
> is at PL 0 and the homeserver refuses its `m.room.power_levels` write, so a
> self-grant cannot work. Keep `join_workspace` unchanged.

### 3. Guided `M_FORBIDDEN` error at the six state-write sites

- Add a variant:
  ```rust
  /// The daemon's Matrix user lacks the workspace power level required to write
  /// this `com.mxagent.*` state event (architecture §9.4 / §14).
  WorkspaceForbidden { room_id: String, event_type: String, required_pl: i64 },
  ```
  with a `Display` like:
  > `the daemon's Matrix user lacks the power level (>= 50) required to write `
  > ``com.mxagent.agent.v1` state in room "!abc:server"; ask the workspace `
  > `creator to grant it with `mx-agent workspace grant --room !abc:server `
  > `--user <this-agent's @mxid>``
  Include **only** room id, event type, and required PL — never tokens,
  signatures, or device keys.
- Add a helper, e.g.
  `fn map_state_write_error(room_id: &str, event_type: &str, err: matrix_sdk::Error) -> WorkspaceError`
  that inspects the Matrix client-API error kind (matrix-sdk 0.18:
  `err.client_api_error_kind()` → `Some(ErrorKind::Forbidden { .. })`, or via
  `err.as_ruma_api_error()`); on `Forbidden` it returns `WorkspaceForbidden{..}`,
  otherwise `WorkspaceError::from(err)`. Confirm the exact accessor name against
  the vendored matrix-sdk 0.18 API during implementation.
- DRY the six sites behind one shared internal helper
  `async fn send_workspace_state(room: &Room, event_type: &str, state_key: &str, content: serde_json::Value) -> Result<(), WorkspaceError>`
  that calls `send_state_event_raw` and routes the error through
  `map_state_write_error(room.room_id().as_str(), event_type, e)`. Replace the
  raw `send_state_event_raw(...).map_err(WorkspaceError::from)` at `agent.rs:164`,
  `heartbeat.rs:252`, `task.rs:416`, `exec.rs:484`, `trust_state.rs:196`,
  `workspace.rs:648` with calls to it. (The helper can live in `workspace.rs` and
  be `pub(crate)`.)

### 4. Tests & doc updates

Covered in [Testing Plan](#testing-plan) and
[Documentation Updates](#documentation-updates).

## Affected Files / Crates / Modules

**Read:** `README.md`, `CONTRIBUTING.md`, `docs/architecture.md` (§9.3/§9.4/§14),
`crates/mx-agent-protocol/src/events.rs` (`state::ALL`).

**Modify:**

- `crates/mx-agent-daemon/src/workspace.rs` — `build_create_room_request` (add
  `power_level_content_override` + `WORKSPACE_AGENT_PL`); new
  `grant_workspace` / `grant_workspace_for_session`; new `GrantWorkspaceOptions`;
  `WorkspaceError::WorkspaceForbidden` + `Display`; `map_state_write_error` +
  `send_workspace_state` helpers; new unit tests.
- `crates/mx-agent-daemon/src/agent.rs` (`:164`),
  `crates/mx-agent-daemon/src/heartbeat.rs` (`:252`),
  `crates/mx-agent-daemon/src/task.rs` (`:416`),
  `crates/mx-agent-daemon/src/exec.rs` (`:484`),
  `crates/mx-agent-daemon/src/trust_state.rs` (`:196`) — route state writes
  through `send_workspace_state`.
- `crates/mx-agent-daemon/src/lifecycle.rs` — `workspace.grant` dispatch +
  method-list entry.
- `crates/mx-agent-daemon/src/lib.rs` (re-exports) — export
  `GrantWorkspaceOptions` / grant fns / `WORKSPACE_AGENT_PL` as the other
  workspace items are (check how `CreateWorkspaceOptions` etc. are re-exported).
- `crates/mx-agent-cli/src/cli.rs` (+ the workspace command handler module) —
  `Grant` subcommand, args, and IPC call.
- `crates/mx-agent-daemon/tests/matrix_integration.rs` — remove the 11 raw
  grants, add the granted-daemon and forbidden-member tests, route any needed
  elevation through the production grant path.
- `docs/architecture.md`, `docs/user-guide.md`, `docs/security-hardening.md`,
  `docs/cli-reference.md`, and `README.md` status row if the command surface row
  changes.

## CLI / API Changes

- **New CLI subcommand:** `mx-agent workspace grant --room <ID|#alias> --user
  <@mxid> [--level <N>]` (creator-only; daemon-mediated; `--json` supported).
  Document in `--help` and `cli-reference.md`.
- **New IPC method:** `workspace.grant` with params
  `{ room: String, user: String, level?: i64 }`, returning a non-secret summary
  `{ room_id, user, level }`. Added to the dispatch and the advertised method
  list in `lifecycle.rs`.
- No change to existing `workspace create/join/attach/status` request/response
  shapes (the override is internal to room creation). No breaking change.

## Data Model / Protocol Changes

- **No** mx-agent event-schema changes (`mx-agent-protocol` untouched).
- The only protocol-adjacent change is the **Matrix `m.room.power_levels`
  content** the daemon now provisions at room creation (per-event-type PLs for
  the six `com.mxagent.*` state types) and edits via the grant command. This is
  a Matrix-room property, not an mx-agent wire format.
- Backward compatibility: existing rooms created before this change keep their
  defaults (creator-only state). Operators can apply the new PL model to an
  existing room by running `workspace grant` for each agent (and, if desired,
  manually tightening `state_default`). Call this out in docs; no migration code.

## Security Considerations

- **Membership ≠ execution.** Loosening PLs (even to `events_default`/per-type
  50) must never become an execution path. The execution gate is unchanged:
  `call`/`exec` resolve the requester key from published agent state via
  `verifying_key_from_agent_state` (`call.rs:400-411`), enforcing
  `key_id_for_verifying_key(pubkey) == signing_key_id` where `key_id =
  SHA256(pubkey)` (`signing.rs:118-122`); trust is keyed on that hash-bound
  `key_id` (`trust.rs:239-243`, `TrustEntry.fingerprint = SHA256(pubkey)`,
  `trust.rs:56`); approval decisions require `sender == local_user`
  (`approval.rs:540`). A republished agent state cannot pair a trusted `key_id`
  with a foreign public key, and a different Matrix user cannot forge an approval
  sender. The spec must preserve all of this — it touches none of it.
- **Integrity / DoS, defense-in-depth.** The per-type PLs are the reason a wide
  `state_default` loosening is *not* the recommended path: a plain member (PL 0)
  is refused on every `com.mxagent.*` state write, so it cannot grief the room by
  overwriting another agent's `agent.v1` / `task.v1` / `invocation.v1` /
  `trust.v1`. This is integrity protection layered *under* the signing gate, not
  a substitute for it.
- **Creator-only grant.** Only PL 100 (the creator, or an already-granted high-PL
  member) can run `workspace grant`; the homeserver enforces this. A non-creator
  attempt yields the same guided `M_FORBIDDEN`.
- **CLI never owns credentials.** The grant write is performed by the daemon that
  holds the creator's Matrix session; the CLI only passes `room`/`user`/`level`
  over IPC. Consistent with the project's CLI/daemon separation.
- **No secrets in output.** The guided error and the grant summary carry only
  room id, Matrix user id, event type, and PL integers — never tokens,
  signatures, or device keys. Reuse the existing redaction posture; nothing new
  should be logged at the write sites beyond this metadata.
- **Unix-only, no `unsafe`, MSRV 1.74.** No new platform assumptions, no new
  dependencies (`Int`/`RoomPowerLevelsEventContent` are already in tree).

## Testing Plan

**Unit (pure, no live server — beside the existing `build_create_room_request`
tests in `workspace.rs`):**

- The request carries a `power_level_content_override`; deserialize it and assert
  `events[com.mxagent.agent.v1] == 50` (and the same for `task.v1`,
  `invocation.v1`, `workspace.v1`, `trust.v1`, `tool.v1`) — drive the assertion
  off `state::ALL` so it can't drift.
- Assert `users_default == 0`, `events_default == 0`, and `state_default ==`
  the chosen value (50 or 100), and that the override does **not** set a `users`
  map (so the creator's default PL 100 is preserved).
- E2EE + PL combined: a `create --e2ee on` request has both the
  `m.room.encryption` `initial_state` and the PL override.
- Guided error: construct a `WorkspaceError::WorkspaceForbidden{..}` and assert
  its `Display` names the room, the event type, the required PL, and the
  `workspace grant` command, and contains no secret-shaped substrings.
- `map_state_write_error`: a non-forbidden Matrix error maps to
  `WorkspaceError::Matrix`; a forbidden one maps to `WorkspaceForbidden`. (If a
  real `matrix_sdk::Error::Forbidden` is hard to synthesize in a unit test, cover
  the kind-detection branch in the live test instead and unit-test only the
  `Display`.)

**Live integration (`tests/matrix_integration.rs`, Tuwunel, `#[ignore]`):**

- **Granted non-creator daemon, no manual grant:** creator creates the workspace
  (production override), creator elevates the joiner via the production
  `workspace grant` path (not a raw `m.room.power_levels` write), joiner
  registers + heartbeats + claims a task + publishes an invocation — all succeed.
- **Plain member is refused:** a member who is *not* granted attempts to overwrite
  another agent's `agent.v1` (and `task.v1`) and gets `M_FORBIDDEN`, surfaced as
  the guided `WorkspaceForbidden` error.
- **Remove/justify the 11 manual grants** (lines 474, 721, 995, 1254, 1502, 2037,
  2456, 2962, 3632, 4309, 4629). Replace each with either nothing (if the
  production override now suffices) or a single shared test helper that drives the
  production grant command. Remaining tests must pass against
  production-provisioned PLs.

**Full gate:** `cargo fmt --check`, `cargo clippy --all-targets --all-features
-- -D warnings`, `cargo build --all`, `cargo test --all`, and the live suite
(`scripts/matrix_integration_test.sh`) all green.

## Documentation Updates

- `docs/architecture.md`: replace the aspirational lines at `:1182` (§9.4) and
  `:1924` (§14) with a concrete **Workspace power-level model** subsection — the
  per-event-type PLs, the creator/agent/member tiers, and how `workspace grant`
  elevates a daemon. Cross-reference the signing/trust gate so PLs are clearly
  integrity-only, not execution.
- `docs/user-guide.md`: in the two-agent setup flow, add the step where the
  creator runs `workspace grant --user <joiner @mxid>` before the second daemon
  registers.
- `docs/security-hardening.md`: document the tier model, why a wide
  `state_default` loosening is discouraged, and that PLs never gate execution.
- `docs/cli-reference.md`: add the `workspace grant` entry (flags, creator-only,
  `--json`).
- `README.md`: if the workspace status row needs it, note the grant command;
  avoid implying any execution-permission change.
- Keep human-readable output the default and `--json` available for the new
  command. Do not imply unimplemented behavior (no revoke command unless added).

## Risks and Open Questions

- **`state_default` 50 vs 100.** Recommendation is **100** (native room metadata
  creator-only; granted agents still write `com.mxagent.*` via the explicit
  `events` entries). Confirm 100 doesn't break any SDK-side room operation the
  daemon performs post-create (none currently writes native room state besides
  creation). If unsure, 50 is the safe Matrix default and still satisfies the
  acceptance criteria. **Needs a decision.**
- **`power_level_content_override` overlay semantics.** The design relies on the
  homeserver overlaying the override on the default content and preserving the
  default `users: {creator:100}` when the override omits `users`. Verify against
  Tuwunel in the live test (assert the creator is PL 100 and can still grant).
  If a homeserver replaces rather than merges, the override must include
  `users:{ <creator>:100 }`, which would require threading the creator's Matrix
  ID into `build_create_room_request` (making it impure) — keep that as a
  fallback only.
- **Exact matrix-sdk 0.18 error accessor.** `client_api_error_kind()` vs
  `as_ruma_api_error()` for detecting `ErrorKind::Forbidden` — confirm the name
  in the vendored crate before wiring `map_state_write_error`.
- **`update_power_levels` ergonomics.** Confirm `Room::update_power_levels`
  exists in 0.18 and performs the read-modify-write; otherwise read the current
  `m.room.power_levels`, mutate the `users` map, and `send_state_event_raw` it.
- **Revoke.** Is `workspace grant --level 0` an acceptable revoke, or is a
  dedicated `workspace revoke` wanted? (Out of scope here; note in docs.)
- **TOOL provisioning with no writer.** `TOOL` state has no live writer; it's
  provisioned for completeness. Confirm this is desired (it costs nothing and
  keeps the override aligned with `state::ALL`).
- **Existing rooms.** No migration code; operators re-grant per agent on
  pre-existing rooms. Confirm acceptable for alpha.

## Implementation Checklist

1. Add `WORKSPACE_AGENT_PL` constant and the `power_level_content_override` to
   `build_create_room_request` (`workspace.rs`), iterating
   `mx_agent_protocol::events::state::ALL`, omitting the `users` map, and setting
   `users_default`/`events_default`/`state_default`.
2. Add the `build_create_room_request` PL unit tests (per-type 50, defaults, no
   `users` map, e2ee+PL combined), mirroring the existing tests at
   `workspace.rs:784`.
3. Add `WorkspaceError::WorkspaceForbidden { room_id, event_type, required_pl }`
   with a guided, secret-free `Display`, plus its unit test.
4. Add `map_state_write_error(...)` (detect `ErrorKind::Forbidden`) and the
   `send_workspace_state(...)` helper; unit-test the mapping where feasible.
5. Route all six state writes (`agent.rs:164`, `heartbeat.rs:252`, `task.rs:416`,
   `exec.rs:484`, `trust_state.rs:196`, `workspace.rs:648`) through
   `send_workspace_state`.
6. Add `GrantWorkspaceOptions`, `grant_workspace`, and
   `grant_workspace_for_session` (`workspace.rs`); re-export from `lib.rs`.
7. Wire `workspace.grant` IPC dispatch + method-list entry in `lifecycle.rs`.
8. Add the `Grant` subcommand + args + IPC call in `mx-agent-cli` with `--json`
   and creator-only help text.
9. Live tests: granted-daemon-succeeds (no manual grant) and
   plain-member-forbidden; remove/justify the 11 manual
   `m.room.power_levels` grants; verify the creator is still PL 100.
10. Update `docs/architecture.md` (§9.4/§14), `docs/user-guide.md`,
    `docs/security-hardening.md`, `docs/cli-reference.md`, and README as needed.
11. Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
    `cargo build --all`, `cargo test --all`, and the live Tuwunel suite; all
    green.
