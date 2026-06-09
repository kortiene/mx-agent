# Correct E2EE Over-Claims in `docs/cli-reference.md` and Guard Against Regression

## Problem Statement

The CLI reference (`docs/cli-reference.md`, added by #261) re-introduces the exact
confidentiality over-claim that #252 removed from the README and user guide. It tells
operators that remote `exec`/`call`/`share` are **end-to-end encrypted** and that the
command, stdin, and output are "encrypted at rest and in flight" and that "only the
specified agent can decrypt."

This is false and security-relevant. Workspaces are created as **unencrypted** Matrix
rooms (`workspace.rs::create_workspace()` never adds an `m.room.encryption` initial-state
event), so every privileged `EXEC_REQUEST`/`EXEC_FINISHED`/`STREAM_CHUNK`/`STREAM_ARTIFACT`/
`CALL_REQUEST`/`CALL_RESPONSE` and every `share` payload travels as a **cleartext timeline
event** readable by the homeserver operator. The requests are Ed25519-signed, but that
provides **integrity/authenticity, not confidentiality**.

The reference even contradicts itself: line 572 already correctly states the workspace room
"is created with E2EE encryption disabled." An operator reading the over-claimed sections may
run sensitive commands or `share` secrets/diffs on a remote agent believing the homeserver
cannot read them, when in fact it can read the full command line, piped stdin, captured
stdout/stderr, and shared payloads.

A secondary gap: `scripts/gen-cli-artifacts.sh` is wired only into `release.yml` (packaging),
not into PR CI, and there is no doc-lint guard against prose E2EE over-claims — so the
#252/#249 correction can silently regress again, exactly as it did here.

## Goals

- Reword every false/over-stated E2EE confidentiality claim in `docs/cli-reference.md`
  (lines 74, 100, 119, 1181, 1271, 1278, 1334) to state the true trust boundary: remote
  `exec`/`call`/`share` are **Ed25519-signed** and authorized by the receiver
  (verify → trust → policy → optional device/approval gates), but transit an
  **unencrypted** Matrix room in this alpha and are therefore **readable by the homeserver
  operator**.
- Make the reference internally consistent with its own line 572 and with the #252
  README/user-guide and #249 architecture.md corrections.
- Add a doc-lint rule (run in PR CI) that fails when prose claims E2EE / end-to-end-encryption
  / confidentiality for `exec`/`call`/`share`/`workspace` traffic, so the correction cannot
  silently regress until #249 lands.
- Wire CLI-artifact/doc-drift verification into PR CI so the CLI reference cannot drift from
  the binary unnoticed.

## Non-Goals

- **Do not** implement workspace E2EE / `m.room.encryption` on room create. That is #249/#240
  and is explicitly out of scope here — this issue only fixes documentation and CI guards.
- Do not change `exec`/`call`/`share` runtime behavior, event schemas, or signing.
- Do not alter the clap command tree, so the generated completions/man artifacts do not change.
- Do not document any unimplemented confidentiality feature as if it exists.

## Relevant Repository Context

- **Architecture.** The CLI is stateless; the daemon (`mx-agent-daemon`) owns the Matrix
  session, signing key, crypto state, policy, trust store, and supervision. Remote `exec`/`call`
  go: CLI → daemon over Unix-socket JSON-RPC → signed Matrix timeline event → receiver daemon
  pipeline `verify(Ed25519) → trust store → deny-by-default policy.toml → optional
  require_verified_device → optional approval → sandbox runner`. **Room membership grants
  nothing.**
- **Workspaces are unencrypted.** `crates/mx-agent-daemon/src/workspace.rs:393-412`
  (`create_workspace()`) sets only visibility/preset and never adds an `m.room.encryption`
  initial-state event. Tracked by #249.
- **Cleartext transit.** The privileged events are sent via `room.send_raw(...)` as plaintext
  timeline events: `exec.rs:318` (`EXEC_REQUEST`), `exec.rs:713`/`exec.rs:1195`
  (`EXEC_FINISHED`), `exec.rs:968` (`STREAM_CHUNK`), `exec.rs:937` (`STREAM_ARTIFACT`),
  `call.rs:230`/`call.rs:526` (`CALL_REQUEST`), `call.rs:381` (`CALL_RESPONSE`). Requests carry
  a detached Ed25519 signature over canonical JSON (`exec.rs:13-15`, `exec.rs:52`) — signed,
  not encrypted.
- **Established corrected wording to mirror** (from #252/#249):
  - `README.md:28` — "Room membership ≠ execution rights — every privileged request is
    Ed25519-signed and checked against deny-by-default local policy."
  - `README.md:117` — "Every privileged request is **Ed25519-signed** and checked against
    **local policy** before running anything …"
  - `docs/architecture.md:144-147` — "In the current alpha, `workspace create` does not enable
    end-to-end encryption … newly created workspaces are unencrypted. Room-level E2EE on create
    is tracked alongside the E2EE production-hardening work (issues #240 and #249)."
  - `docs/cli-reference.md:572` — already correct: room "is created with E2EE encryption
    disabled (workspace state events must be readable to all members)."
- **CI.** `.github/workflows/ci.yml` has jobs `docs`, `shell`, `adw`, `rust`, `cargo-deny`,
  `matrix-integration`. The `docs` job currently only asserts a few files exist. `shell` runs
  `shellcheck scripts/*.sh`. There is no CLI-doc-drift or prose-claim check.
- **Artifact generation.** `scripts/gen-cli-artifacts.sh` generates completions + man pages
  from the binary's clap tree; referenced only in `.github/workflows/release.yml:66`. There is
  no existing snapshot of `cli-reference.md` to diff against, so a true "drift check" requires
  designing one (see Open Questions).
- **Conventions.** Markdown docs under `docs/`; helper scripts under `scripts/` are POSIX/bash,
  `set -euo pipefail`, shellcheck-clean, Unix-only. New scripts must pass `shellcheck`.

## Proposed Implementation

### Part A — Reword the over-claims in `docs/cli-reference.md`

Apply targeted edits. Suggested replacement language (mirror README/architecture phrasing,
keep it factual and alpha-scoped):

- **Line 74** (quick-start comment): `# 6. ...or on a trusted remote agent (signed + E2EE over Matrix).`
  → `# 6. ...or on a trusted remote agent (Ed25519-signed over Matrix; alpha rooms are unencrypted).`
- **Line 100** (architecture bullet): replace "signed, E2EE Matrix-backed REMOTE operations"
  → "signed, Matrix-backed REMOTE operations (Ed25519-signed; the workspace room is
  unencrypted in this alpha, so traffic is readable by the homeserver — see #249)".
- **Line 119** (conventions): replace "signed, end-to-end-encrypted remote operations"
  → "signed remote operations (Ed25519-signed and authorized by the target daemon; not
  end-to-end encrypted in this alpha)".
- **Line 1181** (`exec` description): replace "a signed, E2EE Matrix-backed remote operation"
  → "a signed, Matrix-backed remote operation".
- **Line 1271** (`exec` **E2EE:** note) — rewrite entirely. Remove "end-to-end encrypted",
  "encrypted at rest and in flight", and "Only the specified agent can decrypt". Replace with a
  **Confidentiality** note, e.g.:
  > **Confidentiality:** Remote exec is **Ed25519-signed** for integrity and authenticity, and
  > the receiver authorizes it (verify → trust store → deny-by-default policy → optional
  > verified-device and approval gates). It is **not** end-to-end encrypted in this alpha: the
  > workspace room is created with encryption disabled (see Workspace create, above), so the
  > command line, stdin, and captured output transit as cleartext Matrix timeline events
  > **readable by the homeserver operator**. Confidentiality from the homeserver is not provided
  > until workspace E2EE lands (#249).
- **Line 1278** (`share` description): replace "broadcasts the payload as encrypted room state
  (E2EE) or media" → "broadcasts the payload as a Matrix timeline event (or media for large
  payloads)". Drop the "(E2EE)" qualifier.
- **Line 1307** (`share file` Behavior) — note this currently says "The daemon encrypts and
  uploads the payload"; change "encrypts and uploads" → "uploads" (and confirm/adjust any other
  "encrypt" verbs in share Behavior blocks discovered during edit).
- **Line 1334** (`share` notes): replace "All shares are E2EE; encryption depends on room-wide
  E2EE enablement and device verification for cross-signed trust." → "Shares transit an
  **unencrypted** workspace room in this alpha and are readable by the homeserver operator;
  room-wide E2EE is tracked by #249. Payloads are integrity-checked via their recorded SHA-256
  digest."

> **Verify, don't trust line numbers.** The line numbers come from the issue snapshot; the
> implementing agent must grep for each phrase (`E2EE`, `end-to-end`, `encrypted at rest`,
> `encrypted room state`, `encrypts and uploads`, `Only the specified agent can decrypt`) and
> fix every occurrence, since edits shift line numbers.

### Part B — Doc-lint rule against confidentiality over-claims

Add `scripts/check-doc-claims.sh` (bash, `set -euo pipefail`, shellcheck-clean):

- Scan `docs/cli-reference.md` (and optionally `README.md`, `docs/user-guide.md`) for forbidden
  phrase patterns that assert confidentiality for exec/call/share/workspace traffic, e.g.
  case-insensitive regex matches on: `end-to-end[ -]encrypted`, `\bE2EE\b`, `encrypted at rest`,
  `encrypted room state`, combined with proximity to `exec`/`call`/`share`/`workspace`.
- Because line 572 ("E2EE encryption disabled") and #249 references legitimately mention E2EE,
  the check must avoid false positives. Recommended approach: a **denylist of forbidden
  substrings** that only ever appear in over-claims (e.g. `encrypted at rest and in flight`,
  `All shares are E2EE`, `Only the specified agent can decrypt`, `signed + E2EE`,
  `signed, E2EE`, `end-to-end-encrypted remote`, `encrypted room state (E2EE)`), rather than a
  broad `E2EE` match. Print each offending file:line and exit non-zero.
- Keep the pattern list in the script with a comment pointing at #249 and instructions to relax
  it once workspace E2EE lands.

Wire it into CI (Part C).

### Part C — Wire doc/CLI verification into PR CI

In `.github/workflows/ci.yml`, extend the existing `docs` job (or add a `doc-claims` step) to:

1. Run `scripts/check-doc-claims.sh` (no toolchain needed; pure grep/bash).
2. (CLI-drift) Add a step that builds the CLI and runs `scripts/gen-cli-artifacts.sh` to a temp
   dir to assert the clap tree still generates artifacts cleanly (smoke check). A full
   `cli-reference.md` ⇄ binary diff is **not** trivially available today (the reference is
   hand-written prose, not generated), so the minimal honest guard is: (a) the prose-claim lint,
   and (b) confirm artifact generation succeeds. See Open Questions for a stronger drift check.

   - The artifact-generation smoke step needs the Rust toolchain; place it in (or model it on)
     the existing `rust` job rather than the toolchain-free `docs` job, or gate with the same
     `dtolnay/rust-toolchain@stable` + `Swatinem/rust-cache@v2` setup. The pure-grep doc-claims
     lint should stay in the toolchain-free `docs` job so it fails fast.

`scripts/gen-cli-artifacts.sh` is already shellcheck-clean and in `release.yml`; the new
`check-doc-claims.sh` must also pass the existing `shell` job's `shellcheck scripts/*.sh`.

## Affected Files / Crates / Modules

- `docs/cli-reference.md` — reword lines ~74, 100, 119, 1181, 1271, 1278, 1307, 1334 (verify by
  grep). **Primary change.**
- `scripts/check-doc-claims.sh` — **new** doc-lint script.
- `.github/workflows/ci.yml` — add doc-claims lint step (and optional CLI-artifact smoke step).
- Read-only reference (do **not** modify): `crates/mx-agent-daemon/src/workspace.rs`,
  `crates/mx-agent-daemon/src/exec.rs`, `crates/mx-agent-daemon/src/call.rs`, `README.md`,
  `docs/architecture.md`, `docs/user-guide.md`, `scripts/gen-cli-artifacts.sh`.

## CLI / API Changes

None. No clap command tree, option, output, or exit-code changes. Generated completions and man
pages are unaffected.

## Data Model / Protocol Changes

None. No event schema, persistence, policy, or serialization changes. Signing and the
`EXEC_REQUEST`/`CALL_REQUEST`/`STREAM_*` event shapes are untouched.

## Security Considerations

- This is a **security-facing documentation correction**: it removes a misrepresentation of the
  trust boundary in the dangerous direction (claiming confidentiality that does not exist). The
  corrected text must clearly state the homeserver operator can read commands, stdin, output,
  and shared payloads in this alpha.
- Do not overcorrect into removing the true integrity/authenticity guarantees: requests **are**
  Ed25519-signed and authorized by deny-by-default local policy; keep that accurate.
- The doc-lint script must not log or transmit anything; it is a local grep. No secrets involved.
- Keep alignment with the established invariant phrasing: room membership ≠ execution rights;
  privileged requests Ed25519-signed and policy-checked; Unix-only.
- Reference #249 (workspace E2EE) as the tracking issue for when confidentiality will be
  provided, so the doc states the limitation is known and scoped, not an oversight.

## Testing Plan

- **Doc-lint self-test.** After editing `cli-reference.md`, run `scripts/check-doc-claims.sh`
  locally and confirm it exits 0. Temporarily re-introduce one over-claim phrase and confirm the
  script exits non-zero and prints the offending file:line (manual verification; optionally a
  tiny fixture-based assertion if a test harness for scripts exists).
- **Shellcheck.** Run `shellcheck scripts/check-doc-claims.sh` (CI `shell` job will enforce).
- **Grep audit.** `grep -niE 'e2ee|end-to-end|encrypted at rest|encrypted room state' docs/cli-reference.md`
  and confirm every remaining hit is a *correct* statement (line 572-style "disabled", or a
  reference to #249), with zero confidentiality over-claims.
- **CI dry-run.** Validate `ci.yml` YAML (e.g. `actionlint` if available) and that the new step's
  command runs the script.
- **Artifact smoke (if added).** Confirm `scripts/gen-cli-artifacts.sh "$tmp" target/release/mx-agent`
  produces completions + man pages without error.
- No Rust unit/integration tests are required since no code changes.

## Documentation Updates

- `docs/cli-reference.md` is the document being corrected (the core deliverable).
- Optionally add a one-line cross-reference near the workspace-create note (line ~572) and the
  exec/share confidentiality notes pointing to `docs/architecture.md:144-147` and #249 so all
  three docs tell the same story.
- No README/user-guide changes expected (those were already corrected by #252) — but run the
  doc-lint over them too to confirm no residual over-claims, and fix any found.

## Risks and Open Questions

- **Open question — true CLI-drift check.** `cli-reference.md` is hand-authored prose, not
  generated from clap, so there is no current artifact to diff it against. Options: (a) ship only
  the prose-claim lint + artifact-generation smoke now (recommended, low-risk), or (b) design a
  generated snapshot (e.g. dump `--help` for every subcommand into a committed fixture and diff
  in CI) as a follow-up. The issue's acceptance criterion mentions "doc snapshot/drift check";
  confirm whether the minimal lint suffices for this issue or a full snapshot is expected. **Lean
  toward (a)** to keep scope tight; note (b) as a follow-up issue.
- **False positives in the lint.** A naive `E2EE` match would flag the legitimate line 572 and
  #249 references. Mitigation: denylist of over-claim-only substrings (see Part B). Verify the
  final phrasing chosen in Part A does not itself trip the denylist.
- **Line-number drift.** Editing shifts line numbers; rely on phrase-grep, not the snapshot line
  numbers.
- **Wording review.** The exact replacement prose is security-sensitive; a human reviewer should
  confirm it neither over-claims confidentiality nor under-states the signing/policy guarantees.
- **Workspace E2EE timing.** When #249 lands, the lint denylist and these notes must be relaxed;
  leave an in-script comment so that future work knows where to update.

## Implementation Checklist

1. Grep `docs/cli-reference.md` for `E2EE`, `end-to-end`, `encrypted at rest`,
   `encrypted room state`, `encrypts and uploads`, `Only the specified agent can decrypt`,
   `signed + E2EE`, `signed, E2EE` to enumerate every over-claim (line numbers will have drifted).
2. Reword each per Part A: quick-start (≈74), architecture bullet (≈100), conventions (≈119),
   `exec` description (≈1181), `exec` **E2EE:** note (≈1271 → rewrite as **Confidentiality:**),
   `share` description (≈1278), `share file` Behavior (≈1307), `share` notes (≈1334).
3. Re-grep to confirm zero confidentiality over-claims remain and every surviving E2EE mention is
   the "disabled"/#249 kind. Confirm internal consistency with line ~572.
4. Run the same grep over `README.md` and `docs/user-guide.md`; fix any residual over-claims.
5. Add `scripts/check-doc-claims.sh` (bash, `set -euo pipefail`) implementing the over-claim
   denylist scan; include a comment referencing #249 and how to relax it.
6. `shellcheck scripts/check-doc-claims.sh`; run it locally to confirm exit 0 on the corrected
   docs and non-zero when an over-claim is re-introduced.
7. Edit `.github/workflows/ci.yml`: add a doc-claims lint step to the toolchain-free `docs` job;
   optionally add a `gen-cli-artifacts.sh` smoke step under the `rust` job (toolchain present).
8. Validate the workflow YAML; confirm the doc-claims step runs the script and fails on
   over-claims.
9. (Optional) Add cross-references to `docs/architecture.md:144-147` and #249 in the corrected
   notes for a consistent three-doc story.
10. Final review pass for security-accurate wording (signed/authorized, not confidential; alpha
    rooms unencrypted; homeserver-readable; #249 tracks the fix).
