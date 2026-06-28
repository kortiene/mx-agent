# Document the `event_id` audit anchor in `task create`/`task update` replies + add a `doc_drift` guard

> GitHub issue #377 — `type:docs` `area:tasks` `area:docs` `priority:p2`
> Docs-only follow-up to the closed code issue #367. **No runtime/daemon change.**

## Problem Statement

Issue #367 (already shipped and tested) changed the `task.create` / `task.update`
IPC replies to carry a top-level `event_id` **audit anchor** — the Matrix
`event_id` of the emitted `com.mxagent.task.v1` state event — so a caller can
correlate a signed task mutation to the exact event it produced. The reply type
changed from a bare `TaskState` to `TaskMutation` (the `TaskState` fields
`#[serde(flatten)]`-ed plus one added top-level `event_id`).

`docs/cli-reference.md` was originally not updated, and there was no drift guard
to keep it in sync with the shipped reply shape. The issue asks for two things:

1. Document the new `event_id` reply field in the `task create` and `task update`
   sections of `docs/cli-reference.md`, including how it differs from the existing
   `previous_event_id`.
2. Add a `doc_drift.rs` assertion so the now-shipped reply field cannot silently
   drift back out of the docs (re-diverging to the bare-`TaskState` wording).

### Current state of the working tree (verified at the branch HEAD)

Re-checking the tree *now* (not at the `af2c3c4` snapshot the issue was filed
against) shows the prose half is **already done**, but the guard half is **not**:

- ✅ `docs/cli-reference.md:1724` (`task create`) — already reads: *"JSON output
  returns the full `TaskState` object with all fields **plus a top-level
  `event_id`** — the Matrix event id of the `com.mxagent.task.v1` state event this
  mutation emitted … audit anchor (issue #367)."*
- ✅ `docs/cli-reference.md:1817` (`task update`) — already reads the equivalent
  *"… **plus a top-level `event_id`** … audit anchor (issue #367)."*
- ⚠️ Neither paragraph yet **contrasts** `event_id` (this emission's id) with
  `previous_event_id` (the *prior* revision's id). `previous_event_id` is not
  documented anywhere in `docs/cli-reference.md`. This is the one prose gap
  remaining against acceptance criterion #1.
- ❌ `crates/mx-agent-cli/tests/doc_drift.rs` has **no** assertion referencing
  `event_id`, `audit anchor`, `TaskMutation`, or `#367` (`grep` returns nothing).
  This is the genuine remaining work — acceptance criterion #2.

So the implementer's job is dominated by **adding the drift guard**, plus an
optional one-clause prose refinement to fully satisfy the `previous_event_id`
distinction in acceptance #1. The daemon code is untouched.

## Goals

- Add a `doc_drift.rs` test that fails if the `task create` / `task update`
  sections of `docs/cli-reference.md` stop documenting the top-level `event_id`
  audit-anchor reply field — i.e. the doc cannot silently drift back to the bare
  `TaskState` wording.
- Ensure `docs/cli-reference.md` clearly states, for both `task create --json` and
  `task update --json`, that the reply is the `TaskState` object **plus** a
  top-level `event_id` (the emitted `com.mxagent.task.v1` event id), referencing
  issue #367.
- Clarify the distinction between `event_id` (this emission's id) and
  `previous_event_id` (the prior revision's id) so a reader is not confused by the
  two id-shaped fields.
- Keep the daemon, CLI, IPC, and protocol code untouched (#367 already ships the
  behavior and a unit test).

## Non-Goals

- Any change to the daemon, CLI, IPC, protocol, policy, or sandbox runtime. The
  `TaskMutation` reply shape, signing, and the unit test
  (`task_mutation_reply_flattens_task_and_adds_event_id_anchor`) already exist and
  are correct.
- Re-deriving or re-testing the wire shape of `TaskMutation` (already covered by
  the daemon unit test at `crates/mx-agent-daemon/src/task.rs`).
- Documenting `event_id` in the wiki, README status table, architecture doc, or
  any file other than `docs/cli-reference.md`. (`task list`, `task watch`, and
  `task cancel` replies are unchanged — they still return bare `TaskState` and
  must **not** be retrofitted with an `event_id` claim.)
- Adding a brand-new IPC method or `--json` field. Nothing in the surface changes.
- Backporting an audit anchor to any other reply type.

## Relevant Repository Context

### Architecture / boundaries

- mx-agent is a Rust Cargo workspace; the CLI is stateless and the daemon owns all
  long-lived Matrix state, crypto, policy, and supervision. Tasks are published as
  `com.mxagent.task.v1` **state** events keyed by task id.
- `task create` / `task update` are daemon-IPC-mediated: the CLI forwards the
  request over the local Unix socket and the daemon performs the Matrix write,
  signing CLI-authored `tool`/`exec` actions with its own Ed25519 identity. The
  CLI never holds the signing key (issue #302).
- The reply for these two methods is `TaskMutation` (issue #367):
  `TaskState` `#[serde(flatten)]`-ed + a top-level `event_id`. This is backward
  compatible — an additive top-level key — so existing consumers that parse the
  reply as a bare `TaskState` are unaffected (the extra `event_id` lands in
  `TaskState`'s flattened extra map).

### Shipped #367 code (read-only context — do not modify)

- `crates/mx-agent-daemon/src/task.rs:558-575` — `TaskMutation` struct with the
  doc comment explaining `event_id` is *this* emission's id, distinct from
  `previous_event_id` (the prior revision's id), and that the flattened shape is
  backward compatible.
- `crates/mx-agent-daemon/src/task.rs:516-528` — `publish_task_state` returns the
  emitted `event_id` (`Result<String, _>`).
- `crates/mx-agent-daemon/src/task.rs:629-659` — `create_task_for_session` returns
  `TaskMutation` (built at `:657-658`).
- `crates/mx-agent-daemon/src/task.rs:739-758` — `update_task_for_session` returns
  `TaskMutation` (built at `:757`); the no-signature update path inlines
  `update_task_in_room` so the emitted event id can be captured (`:751-755`).
- `crates/mx-agent-daemon/src/task.rs:1452-1492` — unit test
  `task_mutation_reply_flattens_task_and_adds_event_id_anchor` proving the wire
  shape: `event_id` is top-level, `previous_event_id` is preserved (not
  overwritten), the reply round-trips through `TaskMutation`, and a bare
  `TaskState` parse still works.

### Docs to touch / already touched

- `docs/cli-reference.md:1724` — `task create` output paragraph (already updated;
  may get a one-clause `previous_event_id` refinement).
- `docs/cli-reference.md:1817` — `task update` output paragraph (already updated;
  same optional refinement).
- For reference, the unchanged reply types whose docs must stay as-is:
  - `docs/cli-reference.md:1889` — `task list` → array of bare `TaskState`.
  - `docs/cli-reference.md:2076` — `task cancel` → final bare `TaskState`.

### The drift-guard test file and its conventions

- `crates/mx-agent-cli/tests/doc_drift.rs` embeds doc files at compile time via
  `include_str!`. The relevant const is at line 19:
  `const CLI_REFERENCE: &str = include_str!("../../../docs/cli-reference.md");`.
- Tests are grouped by issue under `// ── Issue #NNN: …` banner comments
  (e.g. the "Issue #313" block starting at `doc_drift.rs:400`). Each test is a
  plain `#[test] fn …()` with a doc comment, using positive
  (`assert!(CONST.contains(…))`) and sometimes negative
  (`assert!(!CONST.contains(stale))`) assertions, each with a message citing the
  issue number.
- The closest pattern to copy is the **substring-loop** guard
  `cli_reference_documents_resource_and_seccomp_keys` at
  `doc_drift.rs:643-658`, which loops over an array of expected key strings and
  asserts each is present in `CLI_REFERENCE`. Other `CLI_REFERENCE` guards live at
  `doc_drift.rs:411` and `:455`.
- The file currently ends at line ~668 (`readme_drops_no_resource_caps_claim`).
  The new test appends after it (or wherever a new `// ── Issue #377` block reads
  cleanly).

### Conventions / constraints to honor

- Unix-only; no Windows assumptions (irrelevant here — pure docs/test).
- No `unsafe`; MSRV is the workspace floor declared in the root `Cargo.toml`
  (`rust-version = "1.93"`; the lower 1.74 figure quoted in some docs is the
  historical/misleading declaration, not the real floor). The new test uses only
  `str::contains` / `str::matches`, well within MSRV either way.
- Preserve human-readable default output and `--json` for automation — the prose
  must keep describing both.
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  and `cargo test --all` must pass. Markdown is not formatted by `cargo fmt`, but
  the new Rust test must be `fmt`/`clippy` clean.

## Proposed Implementation

### 1. Prose: confirm and lightly refine `docs/cli-reference.md`

The two output paragraphs already document the `event_id` audit anchor and cite
issue #367, satisfying the bulk of acceptance #1. Make **only** the following
small change to fully satisfy the "distinguish from `previous_event_id`" clause —
add a short parenthetical to each paragraph (create at `:1724`, update at `:1817`)
contrasting the two id fields. Keep the wording stable and guard-friendly. For
example, append to each sentence something equivalent to:

> … (distinct from `previous_event_id`, which carries the *prior* revision's event
> id; `event_id` is the id of *this* emission).

Keep the existing "purely additive; every prior `TaskState` field is unchanged"
sentence — it correctly signals backward compatibility. Do not reword the existing
"`TaskState` object … plus a top-level `event_id`" phrasing in a way that would
remove the literal token `event_id`, the phrase `audit anchor`, or the `#367`
reference, since the new guard pins those.

If the team prefers to keep the prose exactly as-is (the `previous_event_id`
distinction is a *nice-to-have*, not strictly required by the guard), this step
may be skipped — but adding the one clause is the cheapest way to fully close
acceptance #1, and is recommended.

### 2. Guard: add a `doc_drift.rs` assertion

Add one positive-only test (negative assertions are a poor fit here — see Risks)
following the `cli_reference_documents_resource_and_seccomp_keys` substring-loop
pattern. Place it under a new `// ── Issue #377` banner near the other
`CLI_REFERENCE` task guards (appending at end of file is acceptable).

Recommended shape:

```rust
// ── Issue #377: the task.create/task.update reply now carries a top-level ──────
// `event_id` audit anchor (issue #367). cli-reference.md must keep documenting it
// so the docs cannot silently drift back to the bare-`TaskState` wording.

/// `docs/cli-reference.md` must document the `event_id` audit-anchor reply field
/// for `task create --json` / `task update --json` (the `TaskMutation` shape from
/// issue #367), and must do so for *both* sections — not just one.
#[test]
fn cli_reference_documents_task_event_id_audit_anchor() {
    // Positive: the field, the audit-anchor framing, and the issue reference are
    // all present, so a reader can learn the reply is `TaskState` + `event_id`.
    for needle in ["event_id", "audit anchor", "#367"] {
        assert!(
            CLI_REFERENCE.contains(needle),
            "cli-reference task section must document the event_id audit anchor \
             ({needle:?} missing) (issue #377)"
        );
    }
    // Both the `task create` and `task update` output paragraphs must carry it,
    // so a future edit cannot drop one and leave the other to satisfy the guard.
    assert!(
        CLI_REFERENCE.matches("audit anchor").count() >= 2,
        "both task create and task update must document the event_id audit anchor \
         (issue #377)"
    );
}
```

Notes on the choices:

- The `["event_id", "audit anchor", "#367"]` triple pins the *meaning*, not just
  the bare token: `event_id` (the field), `audit anchor` (the purpose), and `#367`
  (the provenance). All three are present in both paragraphs today.
- The `matches(...).count() >= 2` check guarantees coverage of **both** the
  `create` and `update` paragraphs, so an editor cannot delete the anchor from one
  and still pass. Confirm the count threshold against the chosen phrase — `audit
  anchor` appears exactly twice today (once per paragraph). If step 1's
  refinement changes phrasing, pick a phrase that still appears once per paragraph
  (e.g. count occurrences of `event_id` instead, which would then exceed 2).
- Keep the assertion messages citing **#377** (the doc issue), while the doc text
  cites **#367** (the code issue) — that mirrors the existing convention where the
  guard message references the issue that *added the guard*.

### 3. No runtime change

Do not touch `crates/mx-agent-daemon/src/task.rs` or any other source. The
behavior and its unit test already ship. Adding the guard and (optionally) the
prose clause is the entire change.

## Affected Files / Crates / Modules

| File | Change |
|---|---|
| `crates/mx-agent-cli/tests/doc_drift.rs` | **Add** one `#[test]` (+ optional `// ── Issue #377` banner) asserting the task section documents the `event_id` audit anchor. |
| `docs/cli-reference.md` | **Optional refine** at `:1724` (`task create`) and `:1817` (`task update`): add a one-clause `previous_event_id` distinction. The `event_id`/audit-anchor/#367 wording is already present. |
| `crates/mx-agent-daemon/src/task.rs` | **Read only** — source of the `TaskMutation` truth the guard protects. Do not modify. |

## CLI / API Changes

None. No command, flag, output field, IPC method, or protocol surface changes.
The `--json` reply already includes `event_id` (shipped in #367); this issue only
documents it and guards the doc.

## Data Model / Protocol Changes

None. `TaskMutation` (the `TaskState`-flattened-plus-`event_id` reply) already
exists and is unchanged. No event schema, persistence, policy, or serialization
change.

## Security Considerations

- Pure docs + test change; no secret handling, signing, trust, or policy logic is
  touched.
- The documented `event_id` is a public Matrix event identifier (an audit anchor),
  not a secret — documenting it leaks nothing. Do not, in the prose, suggest that
  the reply or the `event_id` carries any confidentiality guarantee; task state
  events are operator-readable plaintext even under `--e2ee on` (issue #308),
  and the existing `task create`/`update` notes already say so — leave those as-is.
- Daemon/CLI separation is unaffected: the CLI still never sees Matrix tokens or
  device keys; the `event_id` it surfaces comes back over the IPC reply.
- Do not overclaim: the prose must not imply any new behavior beyond surfacing the
  already-emitted event id. Keep "purely additive / backward compatible" framing.

## Testing Plan

- **New documentation drift test** in `crates/mx-agent-cli/tests/doc_drift.rs`:
  `cli_reference_documents_task_event_id_audit_anchor` (name per step 2) — asserts
  the `event_id`, `audit anchor`, and `#367` needles are present in
  `CLI_REFERENCE`, and that the audit-anchor framing appears for both the `task
  create` and `task update` paragraphs (count ≥ 2).
- **Verify the guard actually bites**: before/while writing it, sanity-check that
  the assertions pass against the current (already-updated) doc, and would fail if
  the `event_id` wording were reverted — e.g. temporarily confirm by reasoning or
  a local scratch edit that removing `audit anchor` from one paragraph trips the
  `count() >= 2` check. Revert any scratch edit.
- **Existing daemon unit test** `task_mutation_reply_flattens_task_and_adds_event_id_anchor`
  (`crates/mx-agent-daemon/src/task.rs:1452`) already proves the wire shape; no
  change needed, but it stays the source of truth the doc describes.
- **Regression gate**: `cargo test --all` (the doc_drift tests run as part of the
  `mx-agent-cli` test target), `cargo fmt --check`, and
  `cargo clippy --all-targets --all-features -- -D warnings` must pass.
- No live Matrix / `#[ignore]` integration test is needed (docs-only).

## Documentation Updates

- `docs/cli-reference.md` `task create` / `task update` sections — already carry
  the `event_id` audit-anchor wording; optionally add the `previous_event_id`
  distinction clause (step 1). No other doc file needs changing.
- No README status-table change (the task rows already describe the daemon-IPC
  task surface; the `event_id` reply field is an implementation detail of the
  `--json` output, not a status-level capability).
- No wiki change (the wiki protocol/spec pages describe event schemas, not the IPC
  reply envelope; `event_id` is the Matrix event id, already a core Matrix
  concept).
- No architecture-doc change required; the `TaskMutation` doc comment in
  `task.rs:558-575` is the in-code reference.

## Risks and Open Questions

- **Negative-assertion trap (resolved):** a tempting "stale wording is gone" check
  like `!CLI_REFERENCE.contains("returns the full `TaskState` object")` would be
  *wrong* — the corrected sentence legitimately still contains "the full
  `TaskState` object … plus a top-level `event_id`". Use **positive** assertions
  only; the reply genuinely *is* `TaskState` + `event_id`.
- **Guard brittleness vs. intent:** a drift guard is deliberately brittle so doc
  edits are conscious. Pin stable tokens (`event_id` the field name, `#367` the
  issue ref, `audit anchor` the purpose). If a future editor rewords "audit
  anchor", they must update both the doc and this test in lockstep — that is the
  intended behavior, not a bug. Choosing `event_id` for the count check (instead of
  `audit anchor`) is a slightly more robust alternative if the team expects the
  prose phrasing to evolve.
- **Count threshold:** `audit anchor` appears exactly twice today (once per
  paragraph). If step 1's prose refinement or any future edit changes how many
  times a chosen phrase appears, update the `>= 2` threshold and/or the phrase so
  it still distinguishes "both paragraphs documented" from "only one". Decision
  for the implementer: pick the phrase whose per-paragraph occurrence is exactly
  one so the `>= 2` invariant means "both covered".
- **Is the `previous_event_id` clause required?** Acceptance #1 asks to "clarify
  the distinction from `previous_event_id`", but acceptance #2's guard only needs
  `event_id` + audit-anchor phrasing. Recommendation: add the one clause (cheap,
  fully closes #1) but do **not** make the guard assert on `previous_event_id`
  text, to avoid over-pinning prose that is incidental to the field being
  documented. Confirm with reviewer if they want the guard to also pin
  `previous_event_id`.
- **Why is the prose already present?** The branch already contains the
  `:1724`/`:1817` edits. The implementer should treat them as the desired state,
  verify they still satisfy the guard, and avoid redundantly re-writing them. If a
  prior partial change is reverted/rebased away, the prose edits in step 1 become
  required rather than optional — the guard will then enforce them.

## Implementation Checklist

1. Read `crates/mx-agent-cli/tests/doc_drift.rs` (esp. the `CLI_REFERENCE` const
   at line 19 and the substring-loop guard
   `cli_reference_documents_resource_and_seccomp_keys` at `:643-658`) and the two
   `docs/cli-reference.md` paragraphs at `:1724` (`task create`) and `:1817`
   (`task update`).
2. (Optional, recommended) Refine `docs/cli-reference.md:1724` and `:1817`: append
   a short clause contrasting `event_id` (this emission's id) with
   `previous_event_id` (the prior revision's id). Preserve the existing
   `event_id` / `audit anchor` / `issue #367` tokens and the "purely additive"
   sentence.
3. Add the `// ── Issue #377` banner comment and a positive-only `#[test]`
   (`cli_reference_documents_task_event_id_audit_anchor`) to `doc_drift.rs`,
   following the substring-loop pattern: assert `["event_id", "audit anchor",
   "#367"]` are each present in `CLI_REFERENCE`, plus a count ≥ 2 check on the
   per-paragraph phrase to guarantee both `task create` and `task update` are
   covered. Cite issue #377 in the assertion messages.
4. Do **not** modify `crates/mx-agent-daemon/src/task.rs` or any other runtime
   source.
5. Run `cargo test -p mx-agent-cli --test doc_drift` (or `cargo test --all`) and
   confirm the new test passes against the current docs.
6. Sanity-check the guard bites: confirm (by reasoning or a reverted scratch edit)
   that removing the `event_id` wording from a paragraph would fail the test.
7. Run `cargo fmt --check` and
   `cargo clippy --all-targets --all-features -- -D warnings`; fix any lint/format
   issues in the new test.
8. Confirm no unrelated files changed; the diff should be limited to
   `doc_drift.rs` (and optionally the two `cli-reference.md` paragraphs).
