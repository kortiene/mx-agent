# Public alpha release checklist

This is the **alpha gate**: the checklist a maintainer runs against a candidate
commit to decide whether it is fit to ship as a public alpha release. It exists
so that "is this commit alpha-release ready?" has a concrete, repeatable answer
rather than a judgement call.

> **Alpha status.** `mx-agent` is pre-release software. `call` and `exec`
> (batch and interactive `--pty`) run a daemon-mediated local execution by
> default and become signed Matrix-backed remote operations when `--room`/`--agent`
> target a registered, trusted, policy-allowed remote agent, and a live daemon
> scheduler loop auto-drives signed, assigned tasks. This checklist gates an *alpha*, and is
> deliberately scoped to what the alpha actually ships — see
> [Known limitations](#known-limitations).

## How to use this document

1. Check out the candidate commit on `main`.
2. Work top-to-bottom through the [alpha gate](#alpha-gate). Every **must** box
   has to be checked for the commit to be releasable.
3. Confirm the [known limitations](#known-limitations) are still accurate for
   this commit — the alpha ships *with* these, but they must be the documented
   set, with no new undocumented gap.
4. Keep the [rollback and revocation](#rollback-and-revocation-guidance) section
   to hand so you know how to back out *before* you tag, not after.

A commit is **alpha-release ready** when every must-pass item below is checked,
the known limitations are accurate, and you have read the rollback plan.

## Contents

- [Alpha gate](#alpha-gate)
  - [Build and test gates](#build-and-test-gates)
  - [Security gates](#security-gates)
  - [Documentation gates](#documentation-gates)
  - [Release-mechanics gates](#release-mechanics-gates)
- [Known limitations](#known-limitations)
- [Rollback and revocation guidance](#rollback-and-revocation-guidance)
- [Sign-off](#sign-off)

## Alpha gate

Every item marked **must** is required. Items marked *should* are strongly
recommended; a maintainer may ship the alpha with a *should* unchecked only by
recording the reason in the [sign-off](#sign-off) note.

### Build and test gates

These mirror the checks enforced in CI (`.github/workflows/ci.yml`). Run them
locally on the candidate commit; do not rely on a stale CI run from an earlier
commit.

- [ ] **must** `cargo build --all` succeeds on a clean checkout.
- [ ] **must** `cargo test --all` passes.
- [ ] **must** `cargo fmt --check` reports no diffs.
- [ ] **must** `cargo clippy --all-targets --all-features -- -D warnings` is
      clean (no warnings).
- [ ] **must** `cargo deny check advisories bans licenses sources` passes
      against `deny.toml` (no unvetted advisories or disallowed licenses).
- [ ] **must** `shellcheck scripts/*.sh` is clean (the `shell` CI job).
- [ ] **must** The Matrix integration test passes:
      `scripts/matrix_integration_test.sh --teardown`.
- [ ] **must** CI is green on the exact release commit (all jobs in
      `ci.yml`), not merely on an ancestor.
- [ ] *should* The release packaging workflow builds for every target — trigger
      `release.yml` via `workflow_dispatch` (a dry run that builds and uploads
      artifacts without publishing) and confirm all matrix targets succeed.

### Security gates

`mx-agent` brokers remote command execution, so the security posture is part of
the gate, not an afterthought. See the
[security hardening guide](security-hardening.md) for the full model.

- [ ] **must** Deny-by-default still holds: with no `policy.toml`, every `exec`
      and `call` is denied. This is covered by policy unit tests; confirm they
      pass and that no change has introduced an implicit allow.
- [ ] **must** No secrets, tokens, keys, or credentials are logged or committed.
      Spot-check the diff and run the candidate with `MX_AGENT_LOG_FORMAT=json`
      to confirm `Secret` values render as `***redacted***`.
- [ ] **must** A security review of the changes since the last release has been
      completed (`/security-review`, or an equivalent manual pass over the
      [security-critical areas](../SECURITY.md#security-critical-areas)).
- [ ] **must** Private local-state files keep their modes: `session.json`,
      `signing_key.ed25519`, `trust.json`, the replay cache, the audit log
      (`audit.log` — decision metadata, not secrets, but held to the same
      posture), and the IPC socket are `0600`; their directories are `0700`.
      (Enforced in code and tests; confirm those tests pass.)
- [ ] **must** `SECURITY.md` and the [security hardening guide](security-hardening.md)
      accurately describe what this commit enforces — no control documented as
      shipped that has since regressed.
- [ ] *should* No new dependency was added without a corresponding `deny.toml`
      review (license + advisory + source).

### Documentation gates

The alpha is only usable if the docs match the binary. A maintainer must be able
to follow them end-to-end on the release commit.

- [ ] **must** The [alpha user guide](user-guide.md) two-agent demo runs as
      written against the bundled homeserver on this commit.
- [ ] **must** Every CLI command referenced in the user guide exists and behaves
      as documented (no renamed/removed flags).
- [ ] **must** [Known limitations](#known-limitations) below reflect reality for
      this commit, and the "alpha status" banners in the user guide and security
      guide are still accurate.
- [ ] **must** `README.md` links resolve and its Documentation list includes
      this checklist and the user/security guides.
- [ ] *should* `CHANGELOG`/release notes summarize what changed since the prior
      tag (the release workflow also auto-generates notes via
      `generate_release_notes`).

### Release-mechanics gates

- [ ] **must** The version to tag follows `vMAJOR.MINOR.PATCH` (the `release.yml`
      trigger matches `v*`) and has not been used before.
- [ ] **must** The release is cut from a commit on `main` with green CI, not from
      a feature branch.
- [ ] **must** After tagging, `release.yml` publishes archives **and** the
      `SHA256SUMS` manifest for every target; verify a downloaded archive's
      checksum matches before announcing.
- [ ] *should* The Git tag is annotated and signed.

## Known limitations

These are the documented gaps the alpha ships *with*. They are acceptable for an
alpha; the gate's job is to ensure they remain the *complete, documented* set.
If the candidate commit has a behavior gap not listed here, either fix it or add
it here before release.

- **Live task dispatch defaults to local execution.** A running daemon's
  scheduler loop auto-claims signed, assigned, policy-allowed tasks and runs them
  via local tool/exec dispatch; routing that dispatch through the signed
  Matrix-backed `call`/`exec` transport is opt-in via `MX_AGENT_TASK_DISPATCH=matrix`.
  An approval-required task is held (fail closed) until an operator publishes a
  decision over IPC: the wired scheduler approval gate then auto-runs it on
  `approve` and finalizes it `blocked` on `deny` — it is never auto-run before a
  decision.
- **PTY signal semantics are partial.** Controlling-tty and full Ctrl-C
  semantics for `exec --pty` are intentionally limited; the workspace forbids
  `unsafe`, so PTY/termios use the safe `rustix` path.
- **Very-large-output tuning is still landing.** Large-output artifact mode
  already ships: streams that exceed the timeline budget can be uploaded as
  Matrix media with SHA-256 integrity, optional zstd compression, and a tail
  preview; remaining artifact work is tuning for very large outputs. E2EE
  privileged-event decryption and fail-safe handling for undecryptable events
  ship today, and **production E2EE hardening shipped** (#240/#256): device
  verification UX, cross-signing, and server-side key backup/recovery — see
  `README.md` and roadmap Phase 12.
- **Sandbox is not a security boundary on its own.** The `none`, `bubblewrap`,
  and Docker/Podman container backends are implemented and policy-selectable.
  `read_only_paths` / `writable_paths` filesystem-bind confinement and `network`
  policy are wired end-to-end from the policy engine to the runner — including
  for auto-executed task DAGs. However there is no seccomp filtering, rlimit
  capping, or UID/GID remapping; commands run as the daemon's user. The built-in
  fallback backend is `none` (zero isolation) — operators must choose
  `bubblewrap`/`docker`/`podman`. Bound the blast radius with policy (cwd, env
  scrub, network, path-bind confinement, runtime/output caps) and a real sandbox
  backend. Interactive `exec --pty` does not route through the sandbox backend;
  only the baseline controls (env scrub, cwd, timeout, output cap) apply to the
  PTY path.
- **Workspace rooms are unencrypted; exec/call/share traffic is homeserver-readable.**
  `workspace create` does not enable room-level E2EE (`create_workspace()` never
  adds an `m.room.encryption` initial-state event). Every `EXEC_REQUEST`,
  `EXEC_FINISHED`, `STREAM_CHUNK`, `CALL_REQUEST`, `CALL_RESPONSE`, and `share`
  payload travels as a cleartext Matrix timeline event readable by the homeserver
  operator. Requests are **Ed25519-signed** (integrity/authenticity guaranteed),
  but **not end-to-end encrypted**. Do not send commands, stdin, or payloads you
  need to keep confidential from the homeserver operator until workspace E2EE
  lands (#249).
- **Bundled homeserver is dev-only.** The Tuwunel homeserver in `dev/matrix`
  binds to loopback, disables federation, and is for local testing only — never
  for production identities or data.
- **Single active session per machine.** A machine holds one active Matrix
  session at a time; switching identities requires re-running `auth login`.

## Rollback and revocation guidance

Know how to back out *before* you tag. An alpha release is reversible at three
levels: the release artifact, the published trust, and any leaked credential.

### Rolling back a release

A GitHub Release and its Git tag are the only published surface — there is no
package-registry publish step to yank.

1. **Mark the release as a draft / pre-release or delete it** so users stop
   downloading the bad build:
   ```bash
   gh release edit vX.Y.Z --draft        # hide it, keep the artifacts
   # or
   gh release delete vX.Y.Z --yes        # remove the release (keeps the tag)
   ```
2. **Delete the tag** if the commit itself must not be referenced:
   ```bash
   git push origin :refs/tags/vX.Y.Z     # delete the remote tag
   git tag -d vX.Y.Z                     # delete it locally
   ```
3. **Ship a fix-forward release.** Prefer cutting `vX.Y.(Z+1)` from a corrected
   commit over reusing a version number — never re-tag a different commit with a
   tag users may already have fetched.
4. **Communicate.** Note the pulled version and the reason in the replacement
   release notes so anyone who grabbed the bad archive knows to upgrade.

Because the alpha installs by copying a single self-contained `mx-agent` binary
(see the [user guide](user-guide.md#install)), a user rolls back simply by
replacing it with a known-good archive and verifying the `SHA256SUMS` checksum.

### Revoking trust (a compromised or rotated peer key)

Trust is local and authoritative — the local store always wins over any
room-published trust, so revocation is immediate and does not depend on a peer
cooperating.

```bash
mx-agent trust revoke --agent @peer:matrix.org --key mxagent-ed25519:BASE64...
mx-agent trust list   --room '!workspace:matrix.org'   # confirm it is revoked
```

A revoked key keeps its record for auditability but is rejected for
authorization. A local revocation also overrides any `com.mxagent.trust.v1`
state a room may publish. After revoking, watch the audit log
(`~/.config/mx-agent/audit.log`) for `deny:` entries from the revoked key.

### Revoking your own identity / credentials

If your Matrix access token or the daemon signing key may have leaked (anyone who
can read `session.json` or `signing_key.ed25519` can act as you):

1. **Invalidate the Matrix session** so the access/refresh token is useless:
   ```bash
   mx-agent auth logout              # clears the local session
   ```
   Then, from a trusted client, log the device out server-side and change the
   account password if the credentials themselves may be exposed.
2. **Rotate the signing key.** Remove `signing_key.ed25519` from the data dir so
   the daemon generates a fresh Ed25519 key on next start, then re-publish and
   re-verify your new fingerprint out-of-band with peers:
   ```bash
   mx-agent trust fingerprint        # read the new fingerprint to peers
   ```
3. **Tell your peers to revoke the old key** with `mx-agent trust revoke` (above)
   so any request still signed by the leaked key is denied on their side.

## Sign-off

Record the decision so it is auditable:

```
Commit:        <full SHA>
Candidate tag: vX.Y.Z
Gate run by:   <maintainer>
Date:          <YYYY-MM-DD>
Result:        READY / NOT READY
Waived shoulds: <none | item + reason>
Notes:         <anything a future reader needs>
```

See also: the [security hardening guide](security-hardening.md) for the controls
behind the security gates, the [alpha user guide](user-guide.md) for the
end-to-end flow the documentation gates validate, and
[`SECURITY.md`](../SECURITY.md) for reporting vulnerabilities.
