# Docs: fix §13.5 sandbox-backend list, daemon.log/audit-log wording, stray markup, README `daemon reload`, container cap-drop note

> Spec for GitHub issue #352 (`type:docs`, `area:docs`, `priority:p2`).
> **Docs-only change. No code, protocol, CLI, or behavior changes.**

## Problem Statement

The 2026-06-14 re-assessment (after the #313 docs-drift sweep) surfaced a handful
of residual documentation inaccuracies. They are small, but they either over-claim
capabilities (implying unsupported sandbox backends exist) or leave stray
machine-markup in a shipped doc. The major over-claims are already guarded by
`scripts/check-doc-claims.sh`; these are the leftover nits it does not cover.

The issue lists five items. **Investigation against the current source tree shows
two of the five are based on premises that no longer hold** (see "Relevant
Repository Context" and "Risks and Open Questions"). The spec therefore corrects
the *real* gaps and explicitly tells the implementer **not** to "fix" wording that
is already accurate into something inaccurate.

The five items, with the verified verdict for each:

1. **`docs/architecture.md` §13.5 sandbox list — REAL GAP.** The "Stronger
   controls" bullet list reads `Docker or Podman` / `bubblewrap or firejail` /
   `chroot` / `user namespace` / `seccomp` / …, framed as a menu of available
   options. This implies `firejail` and `chroot` are supported backends. They are
   not — both are **rejected at policy load** (fail-closed validation error). The
   real policy-selectable backends are `none`, `bubblewrap`, `docker`, `podman`.
   §13.5 is also the one sandbox section that still lists `seccomp` without noting
   it is *not* implemented, while every other doc (README, alpha-checklist,
   security-hardening) is careful to say "no seccomp/rlimit/cgroup yet".

2. **"0600 `daemon.log`" wording — NOT STALE; issue premise is incorrect.** The
   issue claims "tracing output goes to stderr (no on-disk daemon.log); the `0600`
   file is the audit log." The source disagrees: a `0600` `daemon.log` **does**
   exist (it captures the daemon's stdout/stderr when running detached), and
   `audit.log` is a **separate** `0600` file. `docs/security-hardening.md` already
   distinguishes them correctly. **Do not change the daemon.log descriptions.** See
   the detailed analysis below; the only valid action here is verification plus an
   optional one-line clarity touch, never a removal or a swap to "audit.log".

3. **`docs/user-guide.md:516-517` stray markup — REAL GAP.** The file ends with
   literal `</content>` and `</invoke>` lines — machine markup that leaked into the
   committed file. Delete them.

4. **`README.md` Quickstart omits `daemon reload` — REAL GAP.** The `daemon reload`
   subcommand exists and ships today, but the Quickstart "Run the daemon" block
   only lists `start` / `status` / `status --json` / `stop`. Add `reload`.

5. **Container `--cap-drop ALL` limitation — PARTIAL GAP.** The issue says this is
   "currently only in code comments." It is in fact **already documented** in
   `docs/security-hardening.md` (the sandbox backend table) and partially implied
   in the README status table. The real gap is `docs/architecture.md` §13.5, the
   canonical system-design doc, which describes the container backend's flags but
   omits the cap-drop deferral. Add one sentence there.

## Goals

- Correct `docs/architecture.md` §13.5 so the **policy-selectable sandbox backends**
  are stated as `none`, `bubblewrap`, `docker`, `podman`, with `firejail`/`chroot`
  explicitly called out as **rejected at policy load** (fail-closed), matching the
  framing already used in README, alpha-checklist, security-hardening, and
  cli-reference.
- Ensure §13.5 does not imply `seccomp` (or rlimit/cgroup capping) is implemented;
  keep it consistent with the "still no seccomp/rlimit/cgroup caps" statement used
  elsewhere.
- Add the container backend's deliberate **no-`--cap-drop ALL`** note to
  `docs/architecture.md` §13.5 (it runs as root; dropping `CAP_DAC_OVERRIDE` would
  block writes to operator-owned `writable_paths`; a `--user` uid mapping is
  deferred) — sourced from `crates/mx-agent-sandbox/src/lib.rs` and consistent with
  the existing security-hardening backend table.
- Delete the stray `</content>` / `</invoke>` markup at the end of
  `docs/user-guide.md`.
- Add `mx-agent daemon reload` to the README Quickstart "Run the daemon" block with
  an accurate one-line description.
- **Verify** the daemon.log/audit.log wording against the source and leave the
  already-correct descriptions intact; record the verification so the moot issue
  item is closed with evidence rather than a wrong edit.

## Non-Goals

- **No code changes.** This is documentation-only. Do not touch
  `crates/mx-agent-sandbox`, the daemon lifecycle, or any Rust.
- **No new sandbox capability.** Do not imply seccomp, rlimit, cgroup capping, or a
  container `--user` mapping exist — they do not. The cap-drop note documents a
  *limitation*, not a feature.
- **No wiki edits.** `wiki/**` is mirrored from a separate source-of-truth folder
  and is out of scope for this issue (the issue scopes to `README.md` and `docs/`).
  An observed wiki inaccuracy (`wiki/Getting-Started.md:84` lists `daemon.log` under
  `~/.local/share/mx-agent/` rather than the runtime dir) is noted in Risks for a
  follow-up, not fixed here.
- **No change to `scripts/check-doc-claims.sh`.** Its denylist already covers the
  E2EE over-claims; these nits are outside its remit and need no new patterns.
- **No removal of the (correct) `daemon.log` references** in README, cli-reference,
  or security-hardening.

## Relevant Repository Context

mx-agent is a Unix-only Rust Cargo workspace: a stateless `mx-agent` CLI plus a
long-lived daemon that owns Matrix state, crypto, policy, signing, and process
supervision. Public alpha, v0.2.1, MSRV 1.93. Docs live in `docs/` (canonical) and
`wiki/` (mirrored separately). `scripts/check-doc-claims.sh` is a CI lint guarding
E2EE confidentiality over-claims via a substring denylist.

### Item 1 — §13.5 sandbox list (verified)

`docs/architecture.md` §13.5 "Sandboxing" (around lines 2087–2134) currently has:

```
Stronger controls:

- Docker or Podman
- bubblewrap or firejail
- chroot
- user namespace
- seccomp
- read-only root filesystem
- writable workspace and temp only
- network disabled by default
```

This is the only place left that frames `firejail` and `chroot` as if they were
available backends. The rest of the tree is already correct and consistent:

- `README.md:51` — backends are `none` (fallback), `bubblewrap`, `docker`, `podman`;
  "`firejail`/`chroot` are rejected at policy load, never silently unsandboxed";
  "still no seccomp/rlimit/cgroup caps".
- `docs/alpha-release-checklist.md:150-163` — same backend list and the
  "no seccomp and no rlimit/cgroup resource capping" caveat.
- `docs/security-hardening.md:519-534` — a backend table with `none`, `bubblewrap`,
  `docker`/`podman`, and a dedicated `firejail`/`chroot` = "Not implemented —
  rejected at policy load" row. Also `:470` ("`firejail`/`chroot` are rejected")
  and `:528`.
- `docs/cli-reference.md:3181-3189` — a clear "Implemented backends vs. accepted
  values" note: the enum *parses* all six values but `firejail`/`chroot` are
  **rejected at policy load**. (Its inline enum comments at `:3130` and the
  field-reference row at `:3160` still list all six values without an inline
  caveat, relying on the following note. This is borderline and **optional** to
  touch — see Risks; the issue does not scope cli-reference.)

So §13.5 is the outlier. The fix is to bring it in line with this established
phrasing.

### Item 2 — daemon.log vs audit.log (verified; issue premise is WRONG)

Source evidence that a `0600` `daemon.log` genuinely exists and holds operational
(stderr/tracing) output when the daemon runs detached:

- `crates/mx-agent-daemon/src/lifecycle.rs:69` — `log_file: runtime_dir.join("daemon.log")`.
- `crates/mx-agent-daemon/src/lifecycle.rs:1449` — "`daemon.log` captures the
  foreground daemon's stdout and stderr…".
- `crates/mx-agent-daemon/src/lifecycle.rs:1921-1932` — unit test asserting
  `daemon.log` is created `0600` regardless of umask (issue #311).
- `crates/mx-agent-cli/tests/daemon_lifecycle.rs:68-74` — integration test:
  `daemon.log` exists after `start` and is `0600`.
- `crates/mx-agent-daemon/tests/matrix_integration.rs:10205+`
  (`live_no_secrets_in_daemon_log_after_login_and_recover`, issue #311) — reads the
  captured `daemon.log`, asserts `0600`, asserts it is non-empty operational output,
  and asserts no secrets leaked into it.

Source evidence that `audit.log` is a **separate** file:

- `crates/mx-agent-daemon/src/lib.rs:76` — `pub use audit::{… AUDIT_FILE_NAME}`.
- `crates/mx-agent-daemon/src/scheduler_loop.rs:639-664` + comments — audit log
  resolves to `~/.config/mx-agent/audit.log` (config dir, with a data-dir
  fallback), append-only newline-delimited JSON policy-decision records.
- `crates/mx-agent-daemon/tests/matrix_integration.rs:734-790` — reads
  `config_dir.join(AUDIT_FILE_NAME)` and asserts allow/deny records (issue #257).

The docs already describe both correctly:

- `docs/security-hardening.md:606-626` — "**Auto-executed task-DAG decisions…**
  `~/.config/mx-agent/audit.log`…" and then "**Operational logs** are separate from
  the audit log and go to stderr… When the daemon runs in the background its
  stdout/stderr are captured to `daemon.log` in the runtime directory; that file is
  created `0600`…". This is accurate.
- `docs/cli-reference.md:3045-3057` — runtime dir lists `daemon.log` (background
  log); config dir holds `audit.log`. Accurate.
- `README.md:219` — "a `daemon.log` for background output". Accurate.

**Conclusion: there is no stale "0600 daemon.log" wording to fix.** The issue's
premise ("no on-disk daemon.log; the 0600 file is the audit log") is incorrect: both
files exist, both are `0600`, and they hold different things. The implementer must
**not** delete the `daemon.log` references or relabel them `audit.log`; doing so
would *introduce* an inaccuracy and contradict shipped tests. The valid work is to
confirm this and, at most, make a small clarity touch (see Proposed Implementation).

### Item 3 — stray markup (verified)

`docs/user-guide.md` last real content line is `515` ("…resolve entries with
`mx-agent approval approve` / `deny`."). Lines `516` (`</content>`) and `517`
(`</invoke>`) are stray machine markup committed by accident. Delete both.

### Item 4 — `daemon reload` (verified, ships today)

The subcommand exists and is wired:

- `crates/mx-agent-cli/src/cli.rs:155-157` — `DaemonCommand::Reload` ("Reload the
  stored session, (re)starting sync/scheduler/heartbeat without …").
- `crates/mx-agent-cli/src/cli.rs:3671,3675-3696` — `daemon_reload` calls the
  `session.reload` IPC method; prints "session reloaded; sync/scheduler/heartbeat
  running".
- `crates/mx-agent-cli/src/cli.rs:3782` — the `daemon status` hint already tells
  users to run `daemon reload` to resume after a re-login (issue #316).

The README Quickstart "Run the daemon" block (`README.md:96-101`) lists `start`,
`status`, `status --json`, `stop` but not `reload`. Add it.

### Item 5 — container cap-drop note (verified; partially already documented)

Source comments in `crates/mx-agent-sandbox/src/lib.rs`:

- `:352-355` (doc comment) and `:417-423` (inline) — the container backend
  deliberately does **not** `--cap-drop ALL`: it runs as root, and dropping
  `CAP_DAC_OVERRIDE` would block writes to a `writable_paths` mount owned by the
  host operator's (non-root) uid; full cap-drop needs a matching `--user` uid
  mapping, which is deferred. It does apply `--security-opt no-new-privileges`.
- `:704` and `:1115-1125` — unit tests assert bubblewrap *does* `--cap-drop ALL`
  and the container backend *does not*.

Already in docs: `docs/security-hardening.md:527` has the parenthetical "(No
`--cap-drop ALL`: the container runs as root and dropping `CAP_DAC_OVERRIDE` would
block writes to operator-owned `writable_paths`; that needs a `--user` mapping,
deferred.)". The README status table (`:51`) notes containers add
`no-new-privileges` but does not explicitly state they omit cap-drop.

Gap: `docs/architecture.md` §13.5 describes the container backend (`-i -t`,
read-only root, env-by-name) at lines ~2124-2134 but omits the cap-drop deferral.
Add a sentence there so the canonical architecture doc matches the code and the
security-hardening table.

### Conventions

- `docs/` is canonical; `wiki/` mirrors from a separate folder (out of scope).
- Tone: precise, fail-closed framing, "implemented vs deferred" called out
  explicitly. Match the existing phrasing already used for backends elsewhere so the
  docs stay internally consistent (and so a future doc-claims lint, if extended,
  would pass).
- Do not imply unimplemented alpha behavior exists.

## Proposed Implementation

Make five surgical doc edits. Each is independent; keep them in one focused PR.

### Edit A — `docs/architecture.md` §13.5: backend list + seccomp accuracy

Rewrite the "Stronger controls" portion of §13.5 (around lines 2097–2106) so it no
longer reads as a menu containing `firejail`/`chroot`/`seccomp` as available
options. Recommended shape (adapt wording to surrounding prose style):

- State plainly: **the policy-selectable sandbox backends are `none` (zero-isolation
  fallback), `bubblewrap`, `docker`, and `podman`.** `firejail` and `chroot` are
  **rejected at policy load** with a dotted-path validation error — they are never a
  silent unsandboxed fallthrough.
- Keep the genuinely-implemented hardening as descriptive capability notes attached
  to the right backend: bubblewrap → user namespace, `--cap-drop ALL`, private
  `/proc`+`/dev`+tmpfs, `--new-session` (batch); container → read-only root,
  `--security-opt no-new-privileges`, `--network none` when denied, env-by-name.
- Explicitly note what is **not** implemented: no `seccomp` filtering and no
  rlimit/cgroup resource capping — matching README:51 and
  alpha-release-checklist.md:159. Do not list `seccomp` as if available.
- "network disabled by default" can stay (it is true — `Network::Deny` default).

Cross-reference the security-hardening backend table and cli-reference note rather
than duplicating the full table.

### Edit B — `docs/architecture.md` §13.5: container cap-drop note

In the container-backend description in §13.5 (near lines 2124–2134, where `-i -t`,
read-only root, and env-by-name are described), add one sentence, e.g.:

> The container backend applies `--security-opt no-new-privileges` but deliberately
> does **not** `--cap-drop ALL`: it runs as root, so dropping `CAP_DAC_OVERRIDE`
> would block writes to a `writable_paths` mount owned by the host operator's
> non-root uid. Full capability dropping is deferred pending a `--user` uid mapping.

This mirrors `mx-agent-sandbox/src/lib.rs:417-423` and `security-hardening.md:527`.
(Edits A and B can be folded into a single coherent §13.5 revision.)

### Edit C — `docs/user-guide.md`: delete stray markup

Delete lines `516` (`</content>`) and `517` (`</invoke>`). The file should end on
the existing line `515` content. Verify the file ends cleanly with a single trailing
newline and no other stray tags.

### Edit D — `README.md`: add `daemon reload` to Quickstart

In the "Run the daemon" fenced block (`README.md:96-101`), add a `reload` line.
Place it logically (e.g. after `stop`, or grouped with the lifecycle commands).
Suggested:

```bash
mx-agent daemon reload                # reload the stored session; (re)start sync/scheduler/heartbeat without a full restart
```

Keep the column alignment of the existing comments. Optionally add a half-sentence
to the surrounding prose (the paragraph at `:103`) tying `reload` to the re-login
flow it supports, but do not over-explain — the command's own `--help` carries the
detail.

### Edit E — daemon.log/audit.log: verify, do not "fix"

1. Re-read `docs/security-hardening.md:606-626` and `docs/cli-reference.md:3045-3057`
   against the source files listed in Relevant Repository Context. Confirm the
   `daemon.log` (runtime dir, `0600`, background stdout/stderr) vs `audit.log`
   (config dir, `0600`, append-only JSON policy decisions) distinction is accurate.
2. **Make no change** that removes or relabels the `daemon.log` references.
3. *Optional, only if it adds clarity without inaccuracy:* in
   `docs/alpha-release-checklist.md` (which mentions neither file by name today) or
   in `security-hardening.md`, you may add a one-line cross-pointer that the
   operational `daemon.log` and the security `audit.log` are two distinct `0600`
   files. Skip this if it risks redundancy — the existing text is already correct.
4. In the PR description, state that the "0600 daemon.log" item was investigated and
   found to be a non-issue (the daemon.log exists and is correctly documented;
   evidence: lifecycle.rs + the #311/#257 tests), so it is closed by verification.

## Affected Files / Crates / Modules

Files to **modify**:

- `docs/architecture.md` — §13.5 sandbox list (Edit A) + container cap-drop note
  (Edit B), lines ~2087–2134.
- `docs/user-guide.md` — delete stray lines 516–517 (Edit C).
- `README.md` — Quickstart "Run the daemon" block, lines ~96–103 (Edit D).
- *(Optional, Edit E step 3)* `docs/alpha-release-checklist.md` or
  `docs/security-hardening.md` — at most a one-line clarity cross-pointer.

Files to **read for accuracy** (do not modify):

- `crates/mx-agent-sandbox/src/lib.rs` — backend behavior, the cap-drop comments
  (`:352-355`, `:417-423`) and tests (`:704`, `:1115-1125`).
- `crates/mx-agent-daemon/src/lifecycle.rs` — `daemon.log` path + 0600 (`:69`,
  `:1449`, `:1921-1932`).
- `crates/mx-agent-daemon/src/scheduler_loop.rs` / `src/audit.rs` — `audit.log`
  path and shape.
- `docs/security-hardening.md:470,505-534,606-626` — backend table + log/audit
  wording (canonical phrasing to match).
- `docs/cli-reference.md:3045-3057,3125-3189` — runtime/config file list +
  "Implemented backends vs. accepted values" note.
- `docs/alpha-release-checklist.md:150-163` — backend list + seccomp caveat.

Do not edit `scripts/check-doc-claims.sh` or any `wiki/**` file.

## CLI / API Changes

None. No command, flag, IPC method, or public API changes. The README edit merely
*documents* the already-shipped `mx-agent daemon reload` subcommand.

## Data Model / Protocol Changes

None. No event schema, policy schema, persistence, or serialization changes.

## Security Considerations

- **No weakening of fail-closed framing.** The §13.5 rewrite must keep the
  "`firejail`/`chroot` rejected at policy load, never silently unsandboxed" guarantee
  visible — the security point is that an unsupported backend name is a hard error,
  not a quiet downgrade to no isolation.
- **Do not over-claim isolation.** The container cap-drop note documents a real
  limitation; it must read as "deferred limitation," not a feature. Keep "no seccomp,
  no rlimit/cgroup" accurate so operators do not assume isolation that is not there.
- **daemon.log vs audit.log accuracy is itself a security property.** Operators rely
  on `audit.log` for non-repudiation and on `daemon.log` being `0600` so secrets in
  operational logs are not world-readable. Mislabeling them in docs could lead an
  operator to ship the wrong file off-box or assume the audit trail lives somewhere
  it does not. This is exactly why Edit E forbids "fixing" the correct wording.
- No secrets, tokens, or device keys appear in this change. Unix-only assumptions
  unchanged; no Windows paths introduced.

## Testing Plan

This is a docs-only change; the gates are the existing CI doc/lint checks plus
manual verification:

- `scripts/check-doc-claims.sh` — must still pass (no new E2EE over-claim
  substrings introduced). Run it after the edits.
- Markdown sanity: confirm `docs/user-guide.md` no longer contains `</content>` or
  `</invoke>` (`grep -n "</content>\|</invoke>" docs/user-guide.md` returns
  nothing) and ends with a single trailing newline.
- Consistency check: `grep -rn "firejail\|chroot" docs/architecture.md` — every
  remaining hit must be in "rejected at policy load" framing, not an
  available-backend list.
- Cross-doc consistency: the §13.5 backend list should match README:51,
  alpha-release-checklist.md:150-163, security-hardening.md:519-534. A quick manual
  diff of the four backend lists confirms they agree (`none`/`bubblewrap`/`docker`/
  `podman`; firejail/chroot rejected; no seccomp/rlimit/cgroup).
- Verify the README `daemon reload` description matches the actual `daemon reload`
  help text / behavior in `crates/mx-agent-cli/src/cli.rs:155-157,3675-3696`.
- No Rust tests change. `cargo test --all` is unaffected (no code touched), but the
  ADW test gate will still run it.

## Documentation Updates

This change *is* the documentation update. Summary of what changes:

- `docs/architecture.md` §13.5 — corrected backend list, seccomp accuracy, container
  cap-drop note.
- `docs/user-guide.md` — stray markup removed.
- `README.md` — `daemon reload` added to Quickstart.
- *(optional)* a one-line daemon.log/audit.log cross-pointer.

No status-table state change is required (no capability changed). No wiki edit
(separate source of truth, out of scope).

## Risks and Open Questions

1. **Two of the five issue items rest on incorrect premises.** Item 2 (daemon.log)
   is moot — the file exists and is documented correctly; the spec handles it by
   verification, not edit. Item 5 (cap-drop "only in code comments") is already
   partly documented in security-hardening.md; the spec narrows the real gap to
   architecture §13.5. **Decision to confirm with maintainer:** is "verify + no edit"
   acceptable for closing item 2, or does the maintainer want the optional clarity
   cross-pointer (Edit E step 3) added regardless? Recommended: verify-only, since
   the existing text is accurate and adding more risks redundancy.

2. **cli-reference.md inline enum comments** (`:3130`, `:3160`) still list all six
   sandbox values without an inline "rejected" caveat, relying on the following note
   (`:3181-3189`). The issue does not scope cli-reference, and the note already
   clarifies it. **Open question:** include a tiny consistency touch (annotate the
   enum comments) in this PR, or leave it? Recommended: leave it (out of issue
   scope; the note suffices), but it is a low-risk add if the maintainer prefers.

3. **Out-of-scope wiki inaccuracy.** `wiki/Getting-Started.md:84` shows
   `daemon.log` under `~/.local/share/mx-agent/` (the data dir) when it lives in the
   runtime dir (`$XDG_RUNTIME_DIR/mx-agent/`). The wiki is mirrored from a separate
   source and is out of scope for this issue. Recommended: file a follow-up issue
   rather than fixing it here.

4. **§13.5 rewrite scope creep.** §13.5 is a long section with PTY/container prose.
   Keep edits to the backend list and the cap-drop sentence; resist rewriting
   adjacent accurate prose.

## Implementation Checklist

1. Read the source-of-truth files listed under "Affected Files … read for accuracy"
   to confirm every claim in this spec still holds at implementation time
   (`lifecycle.rs:69`, sandbox `lib.rs:417-423`, the backend lists in the four docs).
2. **Edit A** — Rewrite `docs/architecture.md` §13.5 "Stronger controls" so the
   policy-selectable backends are `none`/`bubblewrap`/`docker`/`podman`;
   `firejail`/`chroot` are rejected at policy load; `seccomp` and rlimit/cgroup
   capping are explicitly noted as not yet implemented. Match README/alpha-checklist
   phrasing.
3. **Edit B** — Add the container "no `--cap-drop ALL` (runs as root; would block
   operator-owned `writable_paths` writes; `--user` mapping deferred)" sentence to
   the container-backend description in §13.5.
4. **Edit C** — Delete lines 516–517 (`</content>`, `</invoke>`) from
   `docs/user-guide.md`; confirm it ends cleanly after line 515.
5. **Edit D** — Add `mx-agent daemon reload` (with an accurate one-line comment) to
   the README Quickstart "Run the daemon" fenced block; keep comment alignment.
6. **Edit E** — Verify the daemon.log/audit.log wording in
   `security-hardening.md:606-626` and `cli-reference.md:3045-3057` is accurate;
   make **no** removal/relabel. Optionally add one clarity cross-pointer only if it
   does not introduce redundancy. Note the verification verdict in the PR body.
7. Run `scripts/check-doc-claims.sh` — must print "no E2EE confidentiality
   over-claims found."
8. `grep -n "</content>\|</invoke>" docs/user-guide.md` → expect no output.
9. `grep -rn "firejail\|chroot" docs/architecture.md` → every hit must be in
   "rejected at policy load" framing.
10. Manually diff the four backend lists (architecture §13.5, README:51,
    alpha-release-checklist:150-163, security-hardening:519-534) for agreement.
11. Verify the README `daemon reload` wording matches the subcommand's real behavior
    (`cli.rs:155-157`, `3675-3696`).
12. Confirm no Rust files changed; this remains a docs-only PR.
