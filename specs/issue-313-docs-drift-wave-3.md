# Docs Drift Wave 3 — Stale PTY-Sandbox/E2EE Passages, Wrong Paths/Flags, and the Interop-Breaking Public Wiki Protocol Spec

> GitHub issue #313 · labels `type:docs` `area:protocol` `area:docs` `priority:p2`
> Docs-plus-tests change only. No runtime behavior changes.

## Problem Statement

Several documentation passages describe behavior that no longer matches the shipped
implementation, and — most seriously — the public wiki page
`wiki/Stream-and-Protocol-Spec.md` (mirrored to the GitHub wiki by
`.github/workflows/wiki-sync.yml`) documents a wire contract that differs from the
one the code actually produces. A third-party implementer coding against the wiki
would get the `exec.finished` `signal` type wrong, miss a real event type, handle
exit codes that are never produced, and waste effort on a to-device transport that
has zero usage in the tree. Internal docs additionally cite paths, env-var names,
exit codes, a commit stamp, a roadmap phase number, and a Windows transport that do
not exist or are wrong. `doc_drift.rs` does not guard any of these passages, so they
can silently regress.

**Important — the repository has advanced well past the HEAD (`a7680e8`,
2026-06-11) the issue was filed against.** Three follow-up issues landed and
already corrected a large share of the originally-listed passages, and two of the
issue's recommended replacement wordings are now themselves stale:

- **#307** added a *loopback execution confinement floor* (`pty_ipc.rs`
  `build_loopback_pty_spec` resolves `sandbox`/`network`/`env_allowlist`/binds from
  the operator floor — it no longer runs with `..Default::default()`/no policy).
- **#310** routed the PTY through the sandbox backend and made `firejail`/`chroot`
  *rejected at policy load*.
- **#314** *shipped exit code 129* (requester-side timeout) and corrected the
  user-guide "Still landing" sentence and architecture's "exit 129 planned" note.
- **#316** (commit `0df5995`) added an orphan-reaping *restart janitor* with a
  live-pgid sidecar, so architecture now legitimately describes a child supervisor.

This spec therefore corrects **only what genuinely remains**, explicitly overrides
the issue's now-stale replacement wording where the code moved on, and adds the
guards the issue asked for. The bulk of the real remaining work is the **public
wiki**.

## Goals

- Correct the one remaining stale PTY-sandbox passage (`docs/cli-reference.md`
  "baseline controls only") using the *current* loopback-confinement-floor model,
  not the issue's pre-#307 "resolves no policy" phrasing.
- Fix the stale closed-issue / wrong roadmap-phase bullets in
  `docs/alpha-release-checklist.md`, `README.md`, and `docs/user-guide.md`.
- Fix wrong paths, env-var names, exit-code clauses, the commit stamp, the Windows
  named-pipe/IPC-auth-token passages, and the "two test users" count in
  `docs/cli-reference.md`, `docs/architecture.md`, `CONTRIBUTING.md`, and
  `crates/mx-agent-daemon/tests/matrix_integration.rs`.
- Make the public wiki an accurate interop contract: correct `wiki/Stream-and-Protocol-Spec.md`
  (`signal` type, missing event type, exit-code table, to-device transport row,
  `sha256`/`artifact_mxc` examples, `max_events_per_second`), and fix the smaller
  drifts in `wiki/AI-Agent-Orchestration.md`, `wiki/Security-and-Sandboxing.md`,
  `wiki/Getting-Started.md`, and `wiki/Core-Concepts.md`.
- Extend `crates/mx-agent-cli/tests/doc_drift.rs` with negative+positive guards for
  the newly-corrected passages, plus a serde round-trip test proving the corrected
  wiki `exec.finished`/`stream.chunk` examples deserialize against the
  `mx-agent-protocol` schema types.
- Make `grep -rn "does not route through the sandbox"` (already clean) and
  `grep -rn "baseline controls only"` over `README.md`, `docs/`, and `wiki/` return
  nothing; keep all existing checks green; do not touch the live Tuwunel suite.

## Non-Goals

- **No code/behavior changes** beyond docs and the `doc_drift.rs` test file. The
  PTY confinement floor, exit codes, and signal mapping already match the code.
- **Already-shipped passages are out of scope** (do not re-edit): all
  `docs/security-hardening.md` PTY/sandbox passages, the
  `docs/alpha-release-checklist.md` sandbox bullet, `README.md:51`, the user-guide
  "Still landing" sentence, architecture §11.3's "no OS process table" wording, the
  roadmap Windows stance, and the `--e2ee` flag reference — these were corrected by
  #307/#310/#314/#271. Re-verify them only to confirm they are clean.
- **Companion issues own their slices** — do not touch them here:
  - #314 owns `docs/user-guide.md`'s "task↔remote-invocation id unification"
    sentence and exec env/timeout forwarding (already shipped).
  - #303 owns `.github/workflows/release.yml`'s "future work" Windows comment.
  - #302 owns the AI-Agent-Orchestration "fully implemented" status-banner wording
    (correct phrasing depends on its design decision) — fix only the "production
    E2EE hardening remains planned" clause and the `--reason` flag here.
- **Do not add architecture's "no child supervisor" wording** — #316 shipped a real
  restart janitor; that half of the issue's §11 ask is now contradicted by code.
- **Do not "drop exit 129"** from the wiki — #314 shipped it; the wiki exit-code
  table must instead mirror the canonical `docs/architecture.md §5.3`.
- No new public API, no protocol/schema change, no Windows paths or assumptions.

## Relevant Repository Context

- **Workspace** (`Cargo.toml`): six crates — `mx-agent-cli`, `mx-agent-daemon`,
  `mx-agent-protocol`, `mx-agent-ipc`, `mx-agent-policy`, `mx-agent-sandbox`.
  `unsafe_code = "forbid"`, `missing_docs` warns (CI treats warnings as errors),
  MSRV **1.93** (raised from 1.74 for `matrix-sdk 0.18`). Wiki pages live in
  `wiki/` and are the source of truth; a GitHub Action mirrors `wiki/**` to the
  public GitHub wiki on merge to `main` (`.github/workflows/wiki-sync.yml`).
- **Drift guards** live in `crates/mx-agent-cli/tests/doc_drift.rs` and embed docs
  via `include_str!` so failures point at committed source. The file already
  guards #271, #269, #307, #310, and #314 passages. `mx-agent-cli`'s dev/build
  graph includes `mx-agent-protocol` and `mx-agent-daemon`, so schema types and
  `serde_json` are available to the test for a round-trip.
- **Verified code facts** (current HEAD, independently confirmed):
  - `crates/mx-agent-protocol/src/schema.rs:122-123` — `ExecFinished.signal` is
    `Option<String>` (a *signal name*, e.g. `"SIGKILL"`), not an integer.
    Producers map via `signal_name` (`exec.rs`); `artifact_mxc` is always `None` on
    the wire.
  - `crates/mx-agent-protocol/src/events.rs:43` — `com.mxagent.exec.stdin.v1` is a
    real timeline event type.
  - `crates/mx-agent-cli/src/stream.rs` — exit-code producers:
    `EXIT_PROTOCOL_FAILURE=128` (`:49`), `EXIT_STREAM_INTEGRITY=132` (`:53`),
    `EXIT_TIMEOUT=129` (`:57`, issue #314). `resolve_exit_code` (`:286`) passes the
    remote `exit_code` through (clamped to a byte) or maps a signal *name* to
    `128 + signum` (`:262-296`); `signal_number` maps `SIGINT→2`, `SIGQUIT→3`,
    `SIGKILL→9`, `SIGTERM→15`, etc. `chunk_integrity_error` (`:376-404`) flags a
    chunk only when (a) its declared base64 cannot decode, or (b) it *carries* a
    `sha256` that mismatches — and since producers emit `sha256: None`, branch (b)
    is unreachable; a missing digest is tolerated (a pass) in both modes.
  - `crates/mx-agent-cli/src/cli.rs` — exec/call error→exit mapping:
    `NotFound→127`, `EmptyCommand`/`InvalidArgs→64`, `Timeout→129` (`:4308`),
    `Spawn`/`Remote→128`; daemon-unreachable / "daemon rejected" CLI failures →
    `ExitCode::from(3)` (e.g. PTY socket connect at `:4391`); strict-mode integrity
    → `132` (`:4336`). `approval approve|deny` accept only `REQUEST_ID` and `--by`
    — there is no `--reason` flag (`:842-850`).
  - `docs/architecture.md §5.3` (lines ~388-410) is the **canonical exit-code
    table** and is already correct: `0`, `1-125`, `64`, `126` *(planned; currently
    surfaces as 128)*, `127`, `128` (protocol/network failure — and today also a
    policy denial or remote rejection), `128 + signum`, `129` (timeout, #314),
    `132`. The real policy-denial exit **today is 128**, not 126.
  - `crates/mx-agent-daemon/src/trust.rs:92-94` — trust store is
    `<data_dir>/trust.json` (e.g. `$XDG_DATA_HOME/mx-agent/trust.json` /
    `~/.local/share/mx-agent/trust.json`), **not** under `~/.config`.
  - `crates/mx-agent-daemon/src/audit.rs:27` (`AUDIT_FILE_NAME`) — audit log is
    **config-relative** (`$MX_AGENT_CONFIG_DIR` / `$XDG_CONFIG_HOME/mx-agent`),
    not the data dir.
  - `crates/mx-agent-policy/src/file.rs:29` — config-dir override env is
    `MX_AGENT_CONFIG_DIR` (the wiki's `MX_CONFIG_DIR` is wrong).
  - `crates/mx-agent-daemon/src/workspace.rs:448-451` — `workspace create
    --e2ee on` injects an `m.room.encryption` initial-state event (#249 / #296).
  - `crates/mx-agent-daemon/src/pty_ipc.rs:200-211` — loopback PTY builds a
    *confined* `RunSpec` from the operator confinement floor (#307): sandbox,
    network, env allowlist, and read-only/writable binds are applied; only the
    wall-clock timeout is omitted (an interactive session runs until ended, bounded
    by the output cap).
  - `crates/mx-agent-protocol/src/artifact.rs:307` — artifact digests are **base64**
    SHA-256.
  - `crates/mx-agent-daemon/src/exec.rs:968-971` — `max_events_per_second` is an
    internal cap with no policy key; always `None` in production.
  - `scripts/matrix_integration_test.sh` provisions **six** per-run users
    (`USER1`..`USER6`).

## Proposed Implementation

Make targeted edits only. Group the work as below. For each PTY/sandbox or
exit-code passage, mirror the **current** model already documented in
`docs/security-hardening.md` and `docs/architecture.md §5.3` — do not invent new
wording or reuse the issue's pre-#307/#314 phrasing.

### Standard correct wordings to reuse (so the docs stay internally consistent)

- **PTY/sandbox:** "Path and network confinement is enforced end-to-end for both
  **batch** `exec` and interactive `exec --pty`: the PTY path routes the command
  through the same selected sandbox backend as the batch path. A remote
  `--room`/`--agent` PTY enforces the target agent's sandbox/network/path policy
  exactly like batch exec; a **loopback** `exec --pty` (no `--room`/`--agent`)
  applies the operator's loopback *confinement floor* (the configured default
  sandbox backend, network decision, filesystem binds, and env-allowlist scrub),
  with the 64 MiB output cap and no wall-clock timeout."
- **Policy denial exit:** "denied with local exit code **128** today (a dedicated
  `126` is planned; see architecture §5.3)."
- **Chunk `sha256`:** "mx-agent producers do not populate the per-chunk `sha256`
  digest today (`sha256: null`); strict mode fails on a **missing/lost chunk or an
  undecodable (bad-base64) chunk**, not on a digest mismatch (that branch is
  unreachable until producers emit digests)."

### 1. PTY/sandbox — one remaining passage

- `docs/cli-reference.md` (currently `:3170-3175`, the "Implemented backends vs.
  accepted values" admonition): replace "interactive `--pty` has baseline controls
  only. (See the sandbox row in the README status matrix.)" with the standard
  PTY/sandbox wording above. While editing this same paragraph, also align the
  stale "`firejail` and `chroot` are accepted by the parser but are **not**
  implemented backends today" clause with #310 (they are **rejected at policy
  load**) for internal consistency with `docs/security-hardening.md`.

### 2. Stale closed-issue / wrong-phase bullets

- `docs/alpha-release-checklist.md` (E2EE bullet, currently `:147-149`): keep
  "production E2EE hardening shipped (#240/#256)" (the existing #271 guard requires
  both issue numbers) but change "roadmap **Phase 12**" → "roadmap **Phase 16**"
  (Phase 16 = "Hardening and Release"; Phase 12 = "Cancellation and Approval").
- `docs/alpha-release-checklist.md` (workspace-encryption bullet, currently
  `:164-172`): rewrite. The default workspace is still unencrypted, but
  `workspace create --e2ee on` now injects `m.room.encryption` at creation
  (`workspace.rs:448-451`). Remove the false "`create_workspace()` never adds an
  `m.room.encryption` initial-state event" and the "until workspace E2EE lands
  (#249)" framing; state that confidentiality from the homeserver operator requires
  `--e2ee on` (and that state events stay operator-readable even then — keep that
  caveat).
- `README.md:53` (Encryption-on-create row): the sentence "Turning E2EE on by
  default is a separate rollout (issue #240)" miscites the closed E2EE-hardening
  issue as the default-rollout tracker. Drop the `(issue #240)` citation (reword to
  "a separate, not-yet-scheduled rollout") unless an open tracker exists (see Open
  Questions). Do not disturb the `--e2ee`/#308 wording the existing guards rely on.
- `docs/user-guide.md` (currently `:493`): "In this alpha both runners execute on
  your local machine." contradicts signed remote dispatch and the §"Alpha status"
  banner at `:411-424`. Reword to: runners execute locally by default and become
  signed, Matrix-backed remote operations when both `--room` and `--agent` target a
  registered remote agent.

### 3. Paths, flags, stamps, Windows

- `docs/cli-reference.md` (trust-store, currently `:3190`): "(`~/.config/mx-agent/trust.json`
  in the data directory)" is self-contradictory. Correct to the **data** dir:
  `<data_dir>/trust.json` (`$XDG_DATA_HOME/mx-agent/trust.json`, default
  `~/.local/share/mx-agent/trust.json`); `trust.rs:92-94`.
- `docs/cli-reference.md` exit-132 clauses (currently `:1327` and `:3092`):
  qualify "bad encoding or sha256 mismatch" with the standard chunk-`sha256`
  wording above — producers emit no chunk digest today, so only a missing chunk or
  an undecodable encoding can trigger `132`.
- `docs/cli-reference.md:6` "Verified against source at commit `e616908`": refresh
  the stamp (it predates the `--e2ee` flag now documented at `:601`). See Open
  Questions for which value to use.
- Windows alignment (`README.md:60` "Windows was intentionally dropped" is
  canonical):
  - `docs/architecture.md §10.2` (currently `:1452-1456`): remove the
    `Windows:` / `\\.\pipe\mx-agent-daemon` named-pipe block (or replace it with a
    one-line note that mx-agent is Unix-only and the IPC transport is a
    Unix-domain socket); the `release.yml` "future work" comment is owned by #303.
  - `docs/architecture.md` (currently `:2323`) "Cross-platform named pipes." —
    align (drop the cross-platform/Windows framing) for consistency.
  - `docs/roadmap-rust.md` (currently `:606`) already states "Unix-only; Windows
    intentionally dropped" — re-verify only, no edit expected.
- `docs/architecture.md §10.2` (currently `:1463`): "optional local IPC auth token
  stored outside agent-visible env" has no implementation — remove the bullet (or
  mark it explicitly "(not implemented)"). The real access control is socket mode
  `0600` + peer-UID check, already documented in the same list.
- `docs/architecture.md §11` restart-recovery: **no edit** — §11.3 already says
  "no OS process table is consulted" (`:1695`) and §11.4 legitimately describes the
  supervisor + live-pgid restart janitor (`:1706`, #316). Do **not** add a "no
  child supervisor" claim. Confirm this section reads correctly and move on.
- `CONTRIBUTING.md` (currently `:84`): "registers the two test users" → "registers
  the six per-run test users".
- `crates/mx-agent-daemon/tests/matrix_integration.rs` (module doc, currently
  `:115`): "registers the two test users" → six per-run users. (This is a `//!`
  doc comment string; editing it is a docs change, not a behavior change.)

### 4. Public wiki — `wiki/Stream-and-Protocol-Spec.md` (the interop contract)

- **Event namespace (`:14-21`):** add `com.mxagent.exec.stdin.v1` to the timeline
  event listing (`events.rs:43`).
- **`max_events_per_second` (`:55`):** change "policy-controlled" to an internal
  cap with no policy key, unset (`None`) in production (`exec.rs:968-971`). Leave
  `max_output_bytes : policy-controlled` (that one *is* policy-controlled via the
  agent's `max_output_bytes`).
- **Strict-mode / chunk-digest prose (`:69` and `:258`):** these currently claim
  "mx-agent producers always populate it" and "carries a populated `sha256`
  digest". Reconcile to the standard chunk-`sha256` wording above (producers emit
  `null`; strict mode fails on a missing/undecodable chunk). This is required for
  internal consistency once the chunk examples below show `null` — even though the
  issue listed only the examples, the prose directly contradicts them.
- **Stream-chunk examples (`:165` and `:184`):** change `"sha256": "<base64>"` to
  `"sha256": null` in both the UTF-8 and binary chunk examples.
- **`exec.finished` example (`:212-227`):** change `"signal": 9` →
  `"signal": "SIGKILL"` (a name string; `Option<String>`, `schema.rs:122-123`) and
  `"artifact_mxc": "mxc://..."` → `"artifact_mxc": null` (never populated on the
  wire). Update the surrounding prose ("killed by a signal (e.g. SIGKILL = 9)") to
  reference the signal *name*; keep the note that the CLI reports `128 + signum`.
- **Artifact example (`:241`):** the `stream.artifact.v1` `sha256` is shown as
  64-hex but the field is **base64** (`artifact.rs:307`) — replace with a base64
  example digest. (The artifact `sha256` *is* populated; only the per-chunk
  `sha256` is null. Keep them distinct.)
- **Transport table to-device row (`:86-95`):** mark the "Olm ephemeral to-device
  messages" mechanism as **future / not implemented** — there is zero to-device
  usage in the tree; privileged signaling rides **signed Matrix timeline events**
  today. Update the section so a reader does not implement a to-device handshake.
  Also refresh the `:95` implementation-status note ("production hardening work
  remains for device verification UX, cross-signing, and key backup") — that work
  shipped (#256/#260) — for consistency.
- **Exit-code table (`:262-278`):** make it **mirror `docs/architecture.md §5.3`**
  (the canonical source). Concretely:
  - keep `0` and `1-125`;
  - **add `3`** — could not reach the daemon / the daemon rejected the local
    request;
  - **add `64`** — invalid CLI usage (empty command / bad args);
  - mark `126` as *planned (policy denial currently surfaces as `128`)*;
  - keep `127`;
  - keep `128` (protocol/network failure — and today also a policy denial or a
    remote rejection);
  - **keep `129`** (requester-side timeout, #314) — **do not drop it** (the
    issue's "drop 129" instruction predates #314);
  - drop the dedicated `130`/`131` rows (130 is covered by the `128 + N` signal
    rule; 131 "remote rejected" is planned/currently-128);
  - keep `132`;
  - keep the `128 + N` signal-death note.

### 5. Other wiki pages

- `wiki/AI-Agent-Orchestration.md:5`: change "production E2EE hardening remains
  planned" to shipped (e616908/#256). Leave the "fully implemented" status-banner
  wording (owned by #302).
- `wiki/AI-Agent-Orchestration.md` (currently `:159`): remove the nonexistent
  `--reason` flag from `mx-agent approval deny req_… --reason '...'` (the command
  accepts only `REQUEST_ID` and `--by`; `cli.rs:842-850`).
- `wiki/Security-and-Sandboxing.md` (currently `:103`): `MX_CONFIG_DIR` →
  `MX_AGENT_CONFIG_DIR` (`file.rs:29`), and change "denied (local exit code `126`)"
  → exit code **128** today (drop the bare `126`; optionally note 126 is planned).
- `wiki/Security-and-Sandboxing.md` (currently `:251`): the audit log is written to
  the **config** dir (`$MX_AGENT_CONFIG_DIR` / `$XDG_CONFIG_HOME/mx-agent/audit.log`),
  not `~/.local/share/mx-agent/audit.log` (`audit.rs`). (Optionally also reconcile
  the `:32` "Olm for 1:1 to-device signaling" phrase with the to-device-not-used
  fact, for consistency.)
- `wiki/Getting-Started.md` (currently `:250`): "`exit 126` from an exec | Local
  policy denied" → the real denial exit is **128** today; update the row (note 126
  is planned). Keep the "deny-by-default is intentional" remediation guidance.
- `wiki/Core-Concepts.md` (currently `:122`): "It **signs every claim**, versions
  every snapshot…" overstates — privileged **requests/decisions** are
  Ed25519-signed, but task-state writes carry `state_rev`/`previous_event_id` and
  **no signature** (`task.rs:428-454`). Reword to that effect without weakening the
  signing-is-the-execution-gate model.

### 6. Guards — `crates/mx-agent-cli/tests/doc_drift.rs`

Add new `include_str!` constants and tests following the existing
negative-phrase-absent + positive-phrase-present style. Add a clearly-labeled
"Issue #313" section header comment.

New constants needed:

```rust
// `README`, `USER_GUIDE`, `ALPHA_CHECKLIST`, `ARCHITECTURE` already exist — reuse them.
const CLI_REFERENCE: &str = include_str!("../../../docs/cli-reference.md");
const WIKI_PROTOCOL: &str = include_str!("../../../wiki/Stream-and-Protocol-Spec.md");
const WIKI_SECURITY: &str = include_str!("../../../wiki/Security-and-Sandboxing.md");
const WIKI_GETTING_STARTED: &str = include_str!("../../../wiki/Getting-Started.md");
```

New tests (each negative + positive):

1. `cli_reference_pty_routes_through_backend_not_baseline_controls` — negative:
   `!CLI_REFERENCE.contains("baseline controls only")`; positive: the corrected
   paragraph mentions the confinement floor / PTY routing through the selected
   sandbox backend (e.g. `contains("confinement floor")` and
   `contains("exec --pty")`).
2. `alpha_checklist_workspace_e2ee_optin_exists` — negative:
   `!ALPHA_CHECKLIST.contains("until workspace E2EE lands (#249)")` and
   `!ALPHA_CHECKLIST.contains("never adds an `m.room.encryption`")`; positive:
   `ALPHA_CHECKLIST.contains("--e2ee on")`.
3. `cli_reference_trust_store_path_is_data_dir` — negative:
   `!CLI_REFERENCE.contains("`~/.config/mx-agent/trust.json` in the data directory")`;
   positive: the corrected data-dir path string is present (e.g.
   `contains(".local/share/mx-agent/trust.json")` or `contains("data dir")` next to
   `trust.json` — pick a stable substring).
4. `user_guide_not_both_runners_local` — negative:
   `!USER_GUIDE.contains("both runners execute on your local machine")`; positive:
   the corrected sentence names remote dispatch via `--room`/`--agent`.
5. `wiki_protocol_signal_is_name_not_int` — negative:
   `!WIKI_PROTOCOL.contains("\"signal\": 9")`; positive:
   `WIKI_PROTOCOL.contains("\"signal\": \"SIGKILL\"")`. Also assert
   `WIKI_PROTOCOL.contains("com.mxagent.exec.stdin.v1")` and
   `!WIKI_PROTOCOL.contains("\"artifact_mxc\": \"mxc://")`.
6. `wiki_policy_denial_exit_is_128_not_126` — negative: the wiki pages no longer
   present `126` as the *current* denial code in the at-issue rows. Prefer narrow
   substring checks, e.g. `!WIKI_SECURITY.contains("local exit code `126`")` and
   `!WIKI_GETTING_STARTED.contains("`exit 126` from an exec")`; positive: the
   `128`-today wording is present in each.
7. `wiki_exec_finished_and_chunk_examples_deserialize` (acceptance-criterion serde
   round-trip): extract the corrected `content` objects from `WIKI_PROTOCOL` (or, if
   extraction is brittle, embed the exact corrected JSON literally in the test and
   also assert `WIKI_PROTOCOL.contains(...)` that literal so drift fails the test),
   then `serde_json::from_str::<ExecFinished>(...)` and
   `serde_json::from_str::<StreamChunk>(...)` must both `is_ok()`. The chunk literal
   must use `"sha256": null` and the finished literal `"signal": "SIGKILL"`,
   `"artifact_mxc": null`. Verify the example field set exactly matches the struct
   (serde will reject unknown/missing fields) and adjust the wiki example to the
   struct if needed.

Keep all existing tests untouched and green.

## Affected Files / Crates / Modules

Docs / wiki (edit):

- `README.md` (line ~53; verify ~51, ~60 unchanged)
- `docs/cli-reference.md` (~6, ~1327, ~3092, ~3170-3175, ~3190)
- `docs/alpha-release-checklist.md` (~147-149, ~164-172)
- `docs/user-guide.md` (~493)
- `docs/architecture.md` (~1452-1456, ~1463, ~2323; verify §5.3 and §11 unchanged)
- `CONTRIBUTING.md` (~84)
- `crates/mx-agent-daemon/tests/matrix_integration.rs` (module-doc `//!`, ~115)
- `wiki/Stream-and-Protocol-Spec.md` (~14-21, ~55, ~69, ~86-95, ~165, ~184, ~212-227, ~241, ~258, ~262-278)
- `wiki/AI-Agent-Orchestration.md` (~5, ~159)
- `wiki/Security-and-Sandboxing.md` (~103, ~251; optionally ~32)
- `wiki/Getting-Started.md` (~250)
- `wiki/Core-Concepts.md` (~122)

Tests (edit):

- `crates/mx-agent-cli/tests/doc_drift.rs` (add #313 constants + tests)

Read-only references (do not edit — source of truth for wording):

- `docs/security-hardening.md` (PTY/confinement-floor wording to reuse)
- `crates/mx-agent-protocol/src/{schema.rs,events.rs,artifact.rs}`
- `crates/mx-agent-cli/src/{stream.rs,cli.rs}`
- `crates/mx-agent-daemon/src/{pty_ipc.rs,trust.rs,audit.rs,exec.rs,workspace.rs,task.rs}`
- `crates/mx-agent-policy/src/file.rs`
- `scripts/matrix_integration_test.sh`

## CLI / API Changes

None. No command, flag, IPC method, or output format changes. (The docs are being
corrected to match the *existing* CLI surface — e.g. removing the documented-but-
nonexistent `approval deny --reason` flag.)

## Data Model / Protocol Changes

None. No event schema, persistence, policy key, or serialization change. The wiki
corrections bring the *documented* wire contract back into agreement with the
unchanged `mx-agent-protocol` schema (`ExecFinished.signal: Option<String>`,
`artifact_mxc: Option<...>` always `None`, per-chunk `sha256: Option<String>`
always `None`, artifact `sha256` base64, `com.mxagent.exec.stdin.v1` present).

## Security Considerations

- **Do not weaken the security model.** Every touched passage must keep
  "room membership ≠ execution permission — Ed25519 signature + local trust store +
  deny-by-default policy" front and center. The PTY/sandbox rewrite and the
  Core-Concepts "signs every claim" correction must not imply execution is gated by
  encryption, power levels, or membership.
- **Preserve the #269 auth/trust carve-out wording** (CLI never owns Matrix
  credentials otherwise); the existing #269 `doc_drift` guards must keep passing —
  none of the edits here touch those passages.
- **Unix-only is the source of truth** (`README.md:60`). Removing the Windows
  named-pipe block and the unimplemented IPC-auth-token bullet must not re-promise
  Windows or any unimplemented control; do not add Windows paths anywhere.
- **No secrets in examples.** The corrected wiki JSON payloads and any log excerpts
  must contain no real tokens, keys, or device IDs (the existing placeholder IDs are
  fine).
- **Daemon/CLI separation unchanged.** Docs continue to state execution happens in
  the daemon; the CLI is stateless. No redaction/`Secret` code is touched.
- **Do not over-claim shipped behavior.** The E2EE-default-rollout reword must not
  imply E2EE-by-default exists; the to-device row must be marked future, not
  removed-as-if-shipped.

## Testing Plan

- **Doc-drift unit/integration tests** (new, in `doc_drift.rs`): the seven guards
  above (negative + positive), run by the default `cargo test --all` with **no
  homeserver**.
- **Serde round-trip** (new): the corrected wiki `exec.finished` and `stream.chunk`
  `content` examples must `serde_json::from_str` into `ExecFinished` / `StreamChunk`
  successfully (acceptance criterion). This also catches any field-name/shape drift
  between the wiki examples and the schema.
- **Regression**: all existing `doc_drift.rs` tests (#271/#269/#307/#310/#314) must
  stay green.
- **Workspace checks**: `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings`, `cargo build`, `cargo test --all` all green.
- **Grep acceptance gates** (run manually / optionally as a guard):
  `grep -rn "does not route through the sandbox" README.md docs/ wiki/` → empty
  (already true); `grep -rn "baseline controls only" README.md docs/ wiki/` →
  empty after the fix.
- **No change** to the `#[ignore]`d live Tuwunel suite (`scripts/matrix_integration_test.sh`);
  the only edit to `matrix_integration.rs` is its module-doc string.

## Documentation Updates

This change *is* the documentation update. After merge,
`.github/workflows/wiki-sync.yml` publishes the corrected `wiki/**` pages to the
public GitHub wiki automatically — **no workflow change required**. Confirm the
`wiki-sync.yml` trigger still matches `wiki/**` (it does) so the corrected
Stream-and-Protocol-Spec, AI-Agent-Orchestration, Security-and-Sandboxing,
Getting-Started, and Core-Concepts pages go live.

## Risks and Open Questions

1. **`docs/cli-reference.md:6` commit stamp** — which value to use? The ADW phase
   that implements this will not know the final merge commit. Recommended default:
   bump the short hash to the current branch base commit at implementation time, or
   reword to drop the drifting hash (e.g. "Verified against the v0.2.0 source").
   *Decision needed only if a stable, non-drifting stamp is preferred.*
2. **`README.md:53` E2EE-default tracker** — is there an open issue tracking
   "turn E2EE on by default"? If yes, cite it; if not, the safe default is to drop
   the `(issue #240)` citation and call it "a separate, not-yet-scheduled rollout".
   #240 stays referenced in `docs/alpha-release-checklist.md` (the #271 guard
   requires it) — only the README miscitation changes.
3. **Serde round-trip extraction** — parsing the fenced ```json blocks out of the
   wiki is brittle (the file has many code fences). Lower-risk approach: embed the
   exact corrected `content` JSON as a literal in the test *and* assert the wiki
   `contains` that literal, so a future wiki edit that diverges fails the test
   without a fragile parser. Confirm `StreamChunk`/`ExecFinished` do not use
   `#[serde(deny_unknown_fields)]` in a way that rejects the example's field set;
   align the example to the struct if they do.
4. **Wiki strict-mode prose scope creep** — `:69` and `:258` are not in the issue's
   literal bullet list but *directly contradict* the required `sha256: null` example
   change. They are included here because leaving them would publish a
   self-contradictory page. If a reviewer wants to keep scope minimal, the
   contradiction must still be resolved (otherwise the page is internally
   inconsistent) — recommend keeping them in scope.
5. **`firejail`/`chroot` "accepted by the parser" in `cli-reference.md`** — this is
   a #310-era drift in the same paragraph as the `--pty` fix. Recommended to fix it
   in passing for consistency with `security-hardening.md`; flag for reviewer if
   they prefer to defer it to a dedicated follow-up.
6. **Line numbers have shifted** from the issue body (filed at `a7680e8`); always
   locate passages by their distinctive phrase, not the issue's line numbers.

## Implementation Checklist

1. Re-confirm the "already done" set is clean (no edit): `grep -rn "does not route
   through the sandbox" README.md docs/ wiki/` empty; security-hardening PTY
   passages, alpha-checklist sandbox bullet, README:51, user-guide "Still landing",
   architecture §11.3/§11.4, roadmap Windows stance, `--e2ee` flag docs.
2. `docs/cli-reference.md`: replace "baseline controls only" with the standard
   PTY/sandbox wording; align the `firejail`/`chroot` "accepted by parser" clause
   with #310; fix the trust-store path to the data dir; qualify the two exit-132
   `sha256`-mismatch clauses; refresh the `:6` commit stamp.
3. `docs/alpha-release-checklist.md`: change the E2EE-hardening roadmap phase
   12→16; rewrite the workspace-encryption bullet for the `--e2ee on` opt-in.
4. `README.md:53`: drop/replace the `(issue #240)` E2EE-default-rollout citation.
5. `docs/user-guide.md`: fix "both runners execute on your local machine".
6. `docs/architecture.md`: remove the Windows named-pipe block and the
   unimplemented IPC-auth-token bullet in §10.2; align the `:2323` "cross-platform
   named pipes" phrase. Do **not** touch §5.3 or §11.
7. `CONTRIBUTING.md` and `crates/mx-agent-daemon/tests/matrix_integration.rs`
   module-doc: "two test users" → six per-run users.
8. `wiki/Stream-and-Protocol-Spec.md`: add `exec.stdin.v1`; fix
   `max_events_per_second`; reconcile the `:69`/`:258` chunk-`sha256` prose; set
   both chunk examples to `sha256: null`; set `signal: "SIGKILL"` and
   `artifact_mxc: null` in the finished example (+ surrounding prose); change the
   artifact `sha256` example to base64; mark the to-device transport row
   future/not-implemented (+ refresh the `:95` status note); rewrite the exit-code
   table to mirror architecture §5.3 (add 3 and 64, mark 126 planned, **keep 129**,
   drop dedicated 130/131, keep the 128+N note).
9. `wiki/AI-Agent-Orchestration.md`: fix "production E2EE hardening remains
   planned"; remove the `approval deny --reason` flag.
10. `wiki/Security-and-Sandboxing.md`: `MX_CONFIG_DIR`→`MX_AGENT_CONFIG_DIR`; denial
    exit 126→128; audit log path config-dir not data-dir (+ optional `:32` to-device
    reconcile).
11. `wiki/Getting-Started.md`: denial exit 126→128.
12. `wiki/Core-Concepts.md`: soften "signs every claim" to match the
    requests/decisions-signed vs. state-writes-versioned reality.
13. `crates/mx-agent-cli/tests/doc_drift.rs`: add the `#313` section, the new
    `include_str!` constants, the seven guards, and the serde round-trip test.
14. Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
    `cargo build`, `cargo test --all`; confirm both grep gates are empty and all
    existing guards stay green.
