# Fix the Release Pipeline: Retire `macos-13`, Delete Dead Windows Branches, Build `--locked`

> Issue: #303 — *Release pipeline has never published: macos-13 runner retired (24h hang), dead Windows branches break publish.*
> Labels: `type:ci` `area:ci` `priority:p0`
> Spec status: planning only — **do not implement from this document in the planning phase.**

## Problem Statement

The tag-triggered release workflow (`.github/workflows/release.yml`, added in 795a65b/#143) has **never successfully published a GitHub Release**, even though tags `v0.1.0` and `v0.2.0` exist. Both tag runs (v0.1.0 → run 26956917798, v0.2.0 → run 27098363916) hung for exactly 24h00m and were auto-cancelled by GitHub. `gh release list` is empty.

Three independent defects, all in `release.yml`:

1. **Retired runner hangs the build.** The `build x86_64-apple-darwin` matrix entry pins `os: macos-13` (`release.yml:32`), a GitHub-hosted Intel image that has been retired and never schedules. The job recorded **zero steps** on both runs and sat queued until GitHub cancelled the whole run at the 24h cap. Because the `release` (publish) job `needs: build` (`release.yml:91`), publish was skipped both times. The other two targets (`x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`) built in ~2 min.

2. **Dead Windows packaging branches break publish even once the runner is fixed.** The `x86_64-pc-windows-msvc` matrix entry was removed in a135579/#150, but vestiges survive: the `.exe` extension logic (`release.yml:57-59`, used at `:62` and `:66`), the `7z`/`.zip` packaging branch (`release.yml:67-69`), and the `artifacts/*.zip` glob in the publish `files:` list (`release.yml:120`). No matrix target ever produces a `.zip`, so the glob is always unmatched, and with `fail_on_unmatched_files: true` (`release.yml:122`) the publish step would **fail** the moment it ran.

3. **Release builds are not `--locked`.** `release.yml:46` runs `cargo build --release …` with no `--locked`, so shipped binaries may resolve dependencies newer than the committed `Cargo.lock` that `cargo-deny` audited (`ci.yml:105-114`). A published binary may not match what was audited.

Two smaller hygiene gaps: workflow-level `permissions: contents: write` (`release.yml:17-18`) also grants the build jobs write when they only need read; and the header comment (`release.yml:8-10`) says a Windows named-pipe transport "is future work", contradicting the project's settled Unix-only stance (`README.md:60`: "Windows was intentionally dropped").

Net effect: the project cannot ship. The `docs/cli-reference.md:3182` claim that "Release archives ship pre-generated completions (`completions/`) and man pages (`man/`)" is currently false because no archive has ever been published.

## Goals

- The release workflow's macOS-Intel build runs on a **schedulable** runner image so a `workflow_dispatch` dry run finishes all three build jobs in minutes (no 24h queue hang).
- All dead Windows packaging branches are removed so `grep -n 'zip\|\.exe\|7z' .github/workflows/release.yml` returns nothing, and the publish step keeps `fail_on_unmatched_files: true` and passes.
- Release artifacts are built `--locked` (`release.yml:46`), so shipped binaries match the `cargo-deny`-audited `Cargo.lock`.
- `permissions: contents: write` is confined to the `release` (publish) job; the `build` jobs get `permissions: contents: read`.
- The `release.yml` header comment matches the project's Unix-only stance (Windows dropped, not "future work").
- After merge, a maintainer validates via a `workflow_dispatch` dry run and then publishes a `v0.2.x` release so `gh release list` is non-empty and the `docs/cli-reference.md:3182` claim becomes true.

## Non-Goals

- **No Rust code changes.** This is a CI/workflow-only change. Unit/integration/live suites act as regression gates, not as the thing under test.
- **No Windows target or packaging path returns.** Unix-only remains a hard invariant; removing the Windows vestiges is cleanup, not a precursor to re-adding Windows.
- **The broader `--locked` sweep** across `ci.yml` (`ci.yml:75/78/84`) and the test harness is owned by the companion issue **#315** ("CI/supply-chain: MSRV never built, no --locked, mutable action/image pins, no job timeouts, no scheduled audit"). This spec changes `--locked` **only** at `release.yml:46`.
- **Artifact signing / SBOM / provenance attestation** (signing `SHA256SUMS`, `actions/attest-build-provenance`, cosign) is a follow-up that may split into its own issue. It is described here for context but is **not** implemented under #303.
- **No change to `docs/architecture.md`.** Its remaining named-pipe mentions (`architecture.md:1319`, `architecture.md:2090`) are out of scope here; only the `release.yml` header is aligned with `README.md:60`. Flag the architecture-doc tension for the stale-docs sweep (#271) if needed.
- **No change to the `dtolnay/rust-toolchain@stable` toolchain** or MSRV; release builds stay on stable ≥ MSRV 1.74.

## Relevant Repository Context

**This is a pure GitHub Actions / shell change.** No crate source is touched. The owning surface is `.github/workflows/release.yml` (plus its inline bash packaging step). Supporting context:

- **Release workflow** (`.github/workflows/release.yml`): tag-triggered (`on.push.tags: v*`) plus `workflow_dispatch` for dry runs (`release.yml:11-15`). A `build` matrix of three Unix targets (`release.yml:27-36`) builds, packages (completions + man pages via `scripts/gen-cli-artifacts.sh`, `release.yml:64-66`), checksums each archive (`release.yml:74-79`), and uploads artifacts (`release.yml:81-87`). A `release` job downloads all artifacts, aggregates `SHA256SUMS` (`release.yml:99-114`), and publishes via `softprops/action-gh-release@v3` (`release.yml:115-123`).
- **Completion/man generation runs the freshly built binary** (`scripts/gen-cli-artifacts.sh` line 26-29 invokes the passed binary path directly). This is the key architectural constraint for the runner choice: the build runner must be able to **execute** the target binary to generate completions/man pages. A native Intel runner runs an `x86_64-apple-darwin` binary directly; an Apple-Silicon runner (`macos-latest`, arm64) cannot run an Intel binary without Rosetta and would make the package step fragile. → keep a **native Intel** runner for the Intel target; do not cross-compile it on `macos-latest`.
- **Checksum tool selection** (`release.yml:74-79`): macOS ships `shasum`, Linux ships `sha256sum`; the `command -v sha256sum` branch is genuinely required for the macOS↔Linux split and must be **kept**. Only the stale "Git-Bash on Windows" mention in its comment should be trimmed.
- **`cargo-deny`** (`ci.yml:105-114`) audits the committed `Cargo.lock` (advisories, bans, licenses, sources). Building the release `--locked` is what makes "audited == shipped" true.
- **Platform stance** (`README.md:60`): "**Platform: Unix only** (Linux and macOS). Windows was intentionally dropped — the project relies on Unix-domain-socket IPC and Unix process semantics." This is the canonical wording the `release.yml` header should echo.
- **Release process is already documented** in `docs/alpha-release-checklist.md` (the `workflow_dispatch` dry-run gate at lines 65-67; the tag→publish→verify-`SHA256SUMS` gate at lines 115-122; rollback at lines 182-185). This spec's validation steps map onto those existing gates.
- **No YAML/action linter in CI.** There is no `actionlint`/`yamllint` job (ShellCheck only runs on `scripts/*.sh`, `ci.yml:24-31`; the inline bash inside `release.yml` is not linted). The **real** validation is the `workflow_dispatch` dry run plus a tag publish — both maintainer-driven and out of PR-CI reach.

## Proposed Implementation

All edits are in `.github/workflows/release.yml`.

### 1. Replace the retired `macos-13` runner (`release.yml:31-33`)

Change the `x86_64-apple-darwin` matrix entry's `os:` from `macos-13` to a **schedulable native-Intel image**, recommended `macos-15-intel`:

```yaml
- target: x86_64-apple-darwin
  os: macos-15-intel   # native Intel runner; macos-13 was retired (#303)
  archive: tar.gz
```

Rationale and constraints:
- Keep **three** targets (Linux x86_64, macOS Intel x86_64, macOS arm64) — the acceptance criteria require exactly three `.tar.gz` archives.
- It must be a **native Intel** image (not `macos-latest`/arm64 with a cross-target), because `scripts/gen-cli-artifacts.sh` executes the built binary to emit completions/man pages.
- **Verify the exact runner label at implementation time** against GitHub's current runner-image docs; if `macos-15-intel` is not the valid label or no schedulable Intel image remains, fall back to the documented alternative (drop the Intel target — see Risks).
- Add a short inline note (and/or extend the header comment) recording the choice, per the issue's "document the choice in the workflow header" ask.

### 2. Delete the dead Windows packaging branches (`release.yml:57-69`, `:120`)

In the `Package archive and checksum` step, drop everything that only existed for the removed Windows target. The matrix `archive` value is now always `tar.gz`, so the conditional packaging collapses to a single tar.gz path:

- Remove the `ext` variable and the `.exe` suffix logic (`release.yml:57-59`); use the binary name directly at the copy (`:62`) and the `gen-cli-artifacts.sh` call (`:66`).
- Remove the `if [ "${{ matrix.archive }}" = "zip" ]` / `7z … .zip` branch (`release.yml:67-69`); keep only the `tar czf` path.
- Remove the `artifacts/*.zip` line from the publish `files:` list (`release.yml:120`); keep `artifacts/*.tar.gz` and `artifacts/SHA256SUMS`, and keep `fail_on_unmatched_files: true` (`release.yml:122`).
- Trim the stale "Git-Bash on Windows ship `sha256sum`" wording in the checksum comment (`release.yml:74`); keep the `command -v sha256sum` else-`shasum` logic (still needed for macOS vs Linux).

Resulting package step (sketch):

```bash
set -euo pipefail
if [ "${{ github.ref_type }}" = "tag" ]; then
  version="${GITHUB_REF_NAME#v}"
else
  version="dev"
fi
bin="mx-agent"
staging="mx-agent-${version}-${{ matrix.target }}"
mkdir "$staging"
cp "target/${{ matrix.target }}/release/${bin}" "$staging/"
cp README.md "$staging/" 2>/dev/null || true
scripts/gen-cli-artifacts.sh "$staging" "target/${{ matrix.target }}/release/${bin}"
asset="${staging}.tar.gz"
tar czf "$asset" "$staging"
# macOS ships `shasum`; Linux ships `sha256sum`.
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$asset" > "${asset}.sha256"
else
  shasum -a 256 "$asset" > "${asset}.sha256"
fi
echo "asset=${asset}" >> "$GITHUB_OUTPUT"
```

Optional simplification (recommended for cleanliness, not required by acceptance): since `archive` is now always `tar.gz`, the `archive:` matrix key and `.zip` publish glob are both vestigial — the `archive` key may be dropped entirely and the asset extension hardcoded. If dropped, ensure no other step references `${{ matrix.archive }}`. Either way, the `zip`/`.exe`/`7z` grep must come back empty.

### 3. Build release artifacts `--locked` (`release.yml:46`)

```yaml
- name: cargo build --release
  run: cargo build --release --locked --target ${{ matrix.target }} --bin mx-agent
```

`--locked` makes the build fail if `Cargo.lock` is stale, guaranteeing the shipped binary resolves exactly the dependency set `cargo-deny` audited. (The companion `--locked` sweep for `ci.yml` and the test harness is #315; do not touch those here.)

### 4. Least-privilege permissions (`release.yml:17-18`, build job, release job)

Remove the workflow-level block and scope per job:

```yaml
# (delete top-level)
# permissions:
#   contents: write

jobs:
  build:
    permissions:
      contents: read      # checkout only
    ...
  release:
    permissions:
      contents: write     # softprops/action-gh-release creates the Release
    ...
```

The `release` job's same-run `actions/download-artifact@v8` works under the default token with `contents: read`/`write`; only the Release-creation needs `contents: write`. No `actions: read` is required for same-run artifact download. (If the follow-up provenance work lands later, it will add `id-token: write` + `attestations: write` to the `release` job — out of scope here.)

### 5. Align the header comment (`release.yml:8-10`)

Rewrite the "future work" sentence to match `README.md:60`:

```yaml
# Windows is intentionally not a target: the daemon's IPC uses Unix domain
# sockets and the `nix` crate, so `mx-agent` is Unix-only. Windows was
# intentionally dropped (not future work); see README.md and docs/architecture.md.
```

(Keep it factual; do not assert behavior the code doesn't have.)

### 6. Validation (post-merge, maintainer-driven — not PR CI)

- Trigger `release.yml` via `workflow_dispatch` (dry run): confirm all three build jobs schedule and finish in minutes, and each uploads a `.tar.gz` + `.sha256` artifact pair.
- Cut a `v0.2.x` tag from a green-CI `main` commit: confirm the `release` job publishes a Release with exactly three `.tar.gz` archives plus `SHA256SUMS`, `fail_on_unmatched_files: true` passing, and that a downloaded archive contains the binary, `completions/`, and `man/`.
- Confirm `gh release list` is now non-empty.

These map onto `docs/alpha-release-checklist.md:65-67` and `:115-122`.

## Affected Files / Crates / Modules

- `.github/workflows/release.yml` — **all** functional edits (runner image, Windows-branch removal, `--locked`, per-job permissions, header comment).
- `scripts/gen-cli-artifacts.sh` — **read only** (no change); referenced to justify the native-Intel runner constraint.
- `docs/alpha-release-checklist.md` — optional: note the chosen Intel runner image alongside the existing dry-run gate; not required for acceptance.
- `docs/cli-reference.md:3182` — **no edit**; its claim becomes true once a release publishes.
- `README.md:60`, `docs/architecture.md:1319/2090` — **read only**; source of the Unix-only wording and the noted (out-of-scope) named-pipe tension.

No crate `Cargo.toml`, no Rust source, no IPC/protocol code is touched.

## CLI / API Changes

None. No command-line surface, public API, IPC method, or protocol type changes.

## Data Model / Protocol Changes

None. No event schema, persistence, policy, or serialization changes. The published artifact set is unchanged in shape (three `.tar.gz` + `SHA256SUMS`); only the workflow that produces it is fixed.

## Security Considerations

- **Supply chain (`--locked`).** Building release artifacts `--locked` guarantees shipped binaries resolve the same `Cargo.lock` that `cargo-deny` audited (`ci.yml:105-114`). This is the security-relevant core of the change.
- **Least privilege.** Confining `contents: write` to the `release` job removes write capability from the `build` jobs, which only check out source. `GITHUB_TOKEN` keeps default per-job scoping; no token is echoed or exported.
- **No secrets in logs.** The packaging step prints only filenames and `SHA256SUMS` contents (`release.yml:111-114`); no credentials are emitted. Keep it that way — do not add token echoes or `set -x` over secret-bearing lines.
- **Unix-only invariant preserved.** Removing the Windows vestiges and aligning the header reinforce, not weaken, the Unix-only stance. The release matrix stays Linux + macOS; no Windows target or packaging path returns.
- **MSRV / toolchain.** Release builds stay on `dtolnay/rust-toolchain@stable` (`release.yml:39`), which is ≥ MSRV 1.74; the runner-image swap does not change the toolchain.
- **Trust boundary unchanged.** This workflow ships the `mx-agent` binary; it does not touch daemon/CLI separation, signing keys, policy, or the approval gate. The coding agent never sees Matrix tokens or device keys (none are present in this workflow).
- **Integrity caveat (follow-up).** Checksums are still computed on the same runner that built the binary (`release.yml:74-79`) and merely aggregated at publish. Signing `SHA256SUMS` and adding SBOM/provenance attestation would remove that single-runner trust assumption — tracked as the out-of-scope follow-up.

## Testing Plan

This change has **no Rust code**, so the existing suites are pure regression gates and should stay green unchanged:

- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo build --all`, `cargo test --all` (`ci.yml:67-78`).
- ShellCheck (`ci.yml:24-31`) and the doc-claims lint (`ci.yml:19-22/32-38`).
- The live Tuwunel `matrix-integration` job (`ci.yml:116-126`).

Workflow-specific checks (no automated CI for the YAML itself — verify manually / in review):

- **Static greps on the edited file:**
  - `grep -n 'zip\|\.exe\|7z' .github/workflows/release.yml` → **empty**.
  - The release build line at `release.yml:46` contains `--locked`.
  - No top-level `permissions:`; `build` job has `contents: read`; `release` job has `contents: write`.
  - Header comment no longer says Windows is "future work".
- **Optional pre-merge lint:** run `actionlint` locally over `release.yml` (not currently in CI) to catch YAML/shell issues in the inline packaging step before the dry run.
- **`workflow_dispatch` dry run (maintainer, post-merge):** all three build jobs schedule and finish in minutes; each uploads `<archive>.tar.gz` + `.sha256`. This is the canonical proof the `macos-13` hang is gone.
- **Tag publish (maintainer, post-merge):** push `v0.2.x`; the Release contains exactly three `.tar.gz` + `SHA256SUMS`, `fail_on_unmatched_files: true` passes, `gh release list` is non-empty, and a downloaded archive contains the binary + `completions/` + `man/`.

## Documentation Updates

- **`release.yml` header comment** — update to the Unix-only "Windows dropped" wording and note the chosen Intel runner image (in-file; part of the implementation).
- **`docs/alpha-release-checklist.md`** — optional: record the Intel runner image next to the dry-run gate (lines 65-67) so future release captains know which image to expect. Not required for acceptance.
- **`docs/cli-reference.md:3182`** — no edit; the "release archives ship completions/man pages" claim becomes accurate once the first release publishes. (If desired, a maintainer can leave it and simply verify after publish.)
- **No `README.md` change** — `README.md:60` is already correct and is the source the header aligns to.
- **Out of scope:** `docs/architecture.md` named-pipe mentions (`:1319`, `:2090`) — flag for the stale-docs sweep (#271), do not edit here.

## Risks and Open Questions

1. **Intel runner label & longevity (decision needed).** `macos-15-intel` is the recommended replacement, but GitHub's Intel runner labels/availability shift as Intel macOS is phased down. **Confirm the valid current label at implementation time.** If no schedulable native-Intel image exists, the documented fallback is to **drop the `x86_64-apple-darwin` target** entirely — which changes acceptance from three archives to two (Linux x86_64 + macOS arm64) and should be confirmed with a maintainer before merging, since the issue's acceptance criteria assume three targets.
2. **No cross-compile shortcut.** Building `x86_64-apple-darwin` on `macos-latest` (arm64) is rejected: `gen-cli-artifacts.sh` runs the built binary to generate completions/man pages, which would require Rosetta and is fragile. A native Intel runner is the intended path.
3. **Validation is maintainer-driven and not reachable from PR CI.** Neither this ADW phase nor PR CI can push a tag or trigger `workflow_dispatch`; the dry run and real publish are manual post-merge steps. The PR can only assert the static (grep-level) acceptance checks. Plan the human validation explicitly.
4. **`archive` matrix key now redundant.** After the Windows-branch removal it is always `tar.gz`. Decide whether to drop it (cleaner) or keep it as self-documentation; either passes the `zip/.exe/7z` grep.
5. **Follow-up scope (signing/SBOM/provenance).** Recommended approach when it lands: `actions/attest-build-provenance` (needs `id-token: write` + `attestations: write` on the `release` job) and/or signing `SHA256SUMS` (cosign or `gpg`). It may split into its own issue; it is **not** part of #303.
6. **Architecture-doc contradiction unresolved.** `docs/architecture.md` still shows a Windows named-pipe path and lists "Cross-platform named pipes" as future work, which conflicts with the "dropped" framing. Intentionally left out of this issue's scope; note it for #271.

## Implementation Checklist

1. [ ] Edit `release.yml:31-33`: change `os: macos-13` → `os: macos-15-intel` (after confirming the label is currently valid); add an inline note that `macos-13` was retired (#303).
2. [ ] Edit the header comment (`release.yml:8-10`): replace the "future work" wording with the Unix-only / "Windows intentionally dropped" wording matching `README.md:60`; mention the Intel runner choice.
3. [ ] Edit the build step (`release.yml:46`): add `--locked` → `cargo build --release --locked --target ${{ matrix.target }} --bin mx-agent`.
4. [ ] In the package step, remove the `ext`/`.exe` logic (`release.yml:57-59`) and use `${bin}` directly at the copy (`:62`) and the `gen-cli-artifacts.sh` call (`:66`).
5. [ ] Remove the `7z`/`.zip` packaging branch (`release.yml:67-69`); keep only the `tar czf` path.
6. [ ] Trim the stale "Git-Bash on Windows" mention in the checksum comment (`release.yml:74`); keep the `sha256sum`/`shasum` fallback.
7. [ ] Remove `artifacts/*.zip` from the publish `files:` list (`release.yml:120`); keep `artifacts/*.tar.gz`, `artifacts/SHA256SUMS`, and `fail_on_unmatched_files: true`.
8. [ ] (Optional) Drop the now-redundant `archive:` matrix key if nothing else references `${{ matrix.archive }}`.
9. [ ] Remove the top-level `permissions: contents: write` (`release.yml:17-18`); add `permissions: { contents: read }` to the `build` job and `permissions: { contents: write }` to the `release` job.
10. [ ] Verify static acceptance: `grep -n 'zip\|\.exe\|7z' .github/workflows/release.yml` is empty; `--locked` present at the build step; per-job permissions correct.
11. [ ] (Optional) Run `actionlint` locally over `release.yml`.
12. [ ] (Maintainer, post-merge) Run `release.yml` via `workflow_dispatch`; confirm all three build jobs finish in minutes and upload `.tar.gz` + `.sha256` pairs.
13. [ ] (Maintainer, post-merge) Tag `v0.2.x` from green `main`; confirm the Release has three `.tar.gz` + `SHA256SUMS`, downloads contain binary + completions + man pages, and `gh release list` is non-empty.
14. [ ] (Optional) Note the chosen Intel runner image in `docs/alpha-release-checklist.md`.
15. [ ] (Out of scope / follow-up) File or reference the signing + SBOM/provenance issue.
