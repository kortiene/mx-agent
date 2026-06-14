# CI / Supply-Chain Hardening: MSRV Build, `--locked`, SHA-Pinned Actions, Image Digest, Job Timeouts, Scheduled Audit

> Issue: #315 — `type:ci area:ci priority:p2`
> Found by the 2026-06-11 feature-completeness re-assessment (follow-up to epic #274).
> This is a **planning/spec document only**. Do not implement here.

## Problem Statement

CI is functionally green but soft on supply-chain and reproducibility guarantees. Seven concrete gaps make the build less trustworthy than it looks:

1. **MSRV is never built.** `Cargo.toml:16` declares `rust-version = "1.74"`, `clippy.toml` pins `msrv = "1.74"`, and the README/CONTRIBUTING advertise 1.74+, but **every** Rust job uses `dtolnay/rust-toolchain@stable`. Nothing ever compiles the tree on 1.74, so the declared MSRV may silently be wrong. With `matrix-sdk 0.18` in the tree, 1.74 is *plausibly below* the real minimum.
2. **No `--locked`.** No CI cargo invocation uses `--locked` (release.yml's release build is the lone exception — it already has it). CI and the live harness can therefore resolve dependencies newer than the `Cargo.lock` that cargo-deny audited, so the audited graph and the built graph can diverge.
3. **Mutable action pins.** Every `uses:` is a moving tag (`actions/checkout@v6`, `Swatinem/rust-cache@v2`, `EmbarkStudios/cargo-deny-action@v2`, `actions/upload-artifact@v7`, `actions/download-artifact@v8`, `softprops/action-gh-release@v3`, `actions/add-to-project@v2.0.0`, `actions/setup-python@v6`, `actions/setup-node@v6`, `pnpm/action-setup@v6`), and `dtolnay/rust-toolchain@stable` is a moving *branch* ref. A compromised or retagged release flows straight into CI.
4. **Unpinned homeserver image.** The live-test homeserver is `ghcr.io/matrix-construct/tuwunel:latest` (`dev/matrix/docker-compose.yml:10`) with no digest, so the integration suite runs against whatever `:latest` happens to be that day.
5. **No job timeouts.** No `timeout-minutes` anywhere under `.github/workflows/`. A hung `matrix-integration` job (~18–20 min nominal) holds a runner for GitHub's 360-minute default.
6. **Advisories only on push/PR.** `cargo deny check ...` runs only on push/PR (the `cargo-deny` job in `ci.yml`). A newly published RustSec advisory against an already-locked dependency surfaces only on the next push, not when it lands.
7. **Live suite can silently race.** The live suite mutates process-global env (59 `std::env::set_var` calls in `crates/mx-agent-daemon/tests/matrix_integration.rs` at current HEAD). Correctness depends on `--test-threads=1`, which is enforced only by the wrapper (`scripts/matrix_integration_test.sh`) and noted in a single in-file comment (`matrix_integration.rs:3371`). A bare `cargo test -p mx-agent-daemon --test matrix_integration -- --ignored` runs tests in parallel and can race the env mutations with no warning.

The `deny.toml` policy itself is sound and is **out of scope** (justified `RUSTSEC-2026-0173` ignore, strict license allowlist, `yanked = "deny"`, crates.io-only sources).

## Goals

- An **MSRV CI job** compiles the whole workspace on the declared `rust-version`. If 1.74 does not compile the current tree, the same PR raises `rust-version` (and `clippy.toml`, README, CONTRIBUTING) to the *real* minimum and documents the bump. A future `Cargo.toml`/dependency change that breaks the MSRV then fails CI instead of going unnoticed.
- **Every** cargo invocation in `ci.yml`, `release.yml`, the new MSRV/audit jobs, and `scripts/matrix_integration_test.sh` carries `--locked`. An out-of-date `Cargo.lock` fails CI rather than silently re-resolving.
- **Every** `uses:` ref across all workflow files is a full-length (40-hex) commit SHA with a trailing `# vX.Y.Z` comment, including `dtolnay/rust-toolchain`. Dependabot still updates SHA pins correctly.
- The homeserver image in `dev/matrix/docker-compose.yml` is **pinned by digest**, and the live Tuwunel suite (`scripts/matrix_integration_test.sh --teardown`) passes against the pinned image.
- **Every job** in every workflow has a `timeout-minutes`.
- A **scheduled (cron, weekly) + `workflow_dispatch`** workflow runs `cargo deny check advisories`, so new advisories are reported without waiting for the next push. A manual dispatch verifies it.
- A **static regression guard** (`scripts/test_ci_yml.sh`, mirroring the existing `scripts/test_release_yml.sh`) asserts SHA pins, `--locked`, and `timeout-minutes` invariants so they cannot silently regress.
- *(Recommended)* An **in-harness single-thread guard** in `matrix_integration.rs` trips (panics with a pointer to the wrapper script) when two live tests overlap, with a unit-level test covering the guard. The full live suite still passes under `--test-threads=1`.
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo build --all`, and `cargo test --all` stay green on Linux and the macOS IPC job.

## Non-Goals

- **No change to `deny.toml` policy** (advisory ignores, license allowlist, sources). It is already sound.
- **No dependency-tree changes** beyond what is strictly required to make the MSRV job green (the goal is to *measure and declare* the real MSRV, not to lower the dependency floor). Do not downgrade `matrix-sdk`.
- **No new Cargo features, CLI flags, IPC methods, or protocol/event changes.** This is CI/repo plumbing plus a test-only guard.
- **No Windows support** — Unix-only invariant is preserved.
- **No migration off GitHub Actions** and no change to the existing job *topology* beyond adding the MSRV job, the scheduled audit workflow, and `timeout-minutes`.
- **No CHANGELOG infrastructure.** The repo has no `CHANGELOG`; an MSRV bump (if any) is documented in README/CONTRIBUTING, consistent with current convention.
- **No `unsafe`** anywhere, including the optional test-harness guard.

## Relevant Repository Context

**Workspace.** Cargo workspace (`resolver = "2"`), seven member crates (`mx-agent-cli`, `-daemon`, `-protocol`, `-ipc`, `-policy`, `-sandbox`, `-telemetry`). `[workspace.package]` declares `version = "0.2.0"`, `edition = "2021"`, `rust-version = "1.74"` (`Cargo.toml:13-19`). `[workspace.lints.rust]` sets `unsafe_code = "forbid"`, `missing_docs = "warn"`; `[workspace.lints.clippy] all = "warn"`. `Cargo.lock` **is committed** (`git ls-files` confirms), so `--locked` is viable today.

**MSRV is declared in five places that must stay in sync:**
- `Cargo.toml:16` — `rust-version = "1.74"`
- `clippy.toml` — `msrv = "1.74"`
- `README.md:8` — MSRV badge (`rustc-1.74%2B`, two occurrences in the URL)
- `README.md:72` and `README.md:178` — prose ("Rust stable toolchain, **1.74+**"; "MSRV: 1.74")
- `CONTRIBUTING.md:24` and `CONTRIBUTING.md:74-75` — prose ("Rust stable toolchain, 1.74+ (the project MSRV)"; "don't use APIs newer than Rust 1.74…")

**Workflows (`.github/workflows/`), six files after this work (five today):**
- `ci.yml` — jobs: `docs`, `shell`, `adw`, `adw-sdlc` (Node 20/22 matrix), `rust` (fmt/clippy/build/test/CLI-artifact smoke), `rust-macos` (IPC crate on macOS), `sandbox-linux` (real bwrap), `cargo-deny`, `matrix-integration`. Triggers: `pull_request` + `push: branches:[main]`.
- `release.yml` — `build` matrix (linux-x86_64, macos-15-intel, macos-latest arm64) + `release`/publish. The release build already uses `--locked` (`release.yml:47`). Has scoped per-job `permissions:`.
- `project-sync.yml` — `add-to-project` (single third-party action `actions/add-to-project@v2.0.0`).
- `wiki-sync.yml` — `sync` (`actions/checkout` only; rest is inline bash). Has `permissions: contents: write` and a `concurrency` group.
- `populate-github.yml` — `populate` (`actions/checkout` + `actions/setup-python`). Has scoped `permissions:`.
- *(new)* `audit.yml` — scheduled advisories run (this work).

**Cargo invocations to touch (line numbers from current HEAD; the issue's line numbers predate recent commits and have shifted — locate by content):**
- `ci.yml` — `cargo clippy --all-targets --all-features -- -D warnings` (~:104), `cargo build --all` (~:107), `cargo test --all` (~:110), `cargo build --release -p mx-agent-cli` (~:116), `cargo clippy -p mx-agent-ipc --all-targets -- -D warnings` (~:133), `cargo test -p mx-agent-ipc` (~:135), `cargo test -p mx-agent-sandbox` (~:167), `cargo test -p mx-agent-daemon --test task_orchestration_e2e ...` (~:170). `cargo fmt --check` (~:101) does **not** resolve deps and needs no `--locked`.
- `release.yml:47` — already `--locked` (no change; the `scripts/test_release_yml.sh` guard already enforces it).
- `scripts/matrix_integration_test.sh` — `cargo build -p mx-agent-cli --bin mx-agent` (:116) and `cargo test -p mx-agent-daemon --test matrix_integration -- --ignored --nocapture --test-threads=1` (:137). For the test invocation, `--locked` is a cargo flag and must appear **before** the `--` separator.

**Existing structural-test pattern.** `scripts/test_release_yml.sh` is a pure-bash static checker that greps `release.yml` for invariants (no Windows remnants, `--locked` on the release build, schedulable Intel runner, least-privilege permissions, header wording). It is run in the `shell` CI job (`ci.yml`) and is ShellCheck-clean (the `shell` job runs `shellcheck scripts/*.sh`). This is the established home for "workflow can't silently regress" guards and is the model for `scripts/test_ci_yml.sh`.

**Live integration harness.** `scripts/matrix_integration_test.sh` boots the throwaway Tuwunel homeserver, registers fresh-per-run users, builds the CLI binary, and runs the `#[ignore]`d suite with `--test-threads=1 --nocapture`. The suite (`crates/mx-agent-daemon/tests/matrix_integration.rs`, ~10k lines) makes 59 `std::env::set_var` calls (`MX_AGENT_DATA_DIR`, `MX_AGENT_CONFIG_DIR`) and is correct only single-threaded; `matrix_integration.rs:3371` documents this in a comment. Tests already `use std::sync::atomic::{AtomicBool, Ordering}` and `std::sync::{Arc, Mutex}`, and some are `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]` (the per-test runtime is multi-threaded; *test functions* are serialized only by `--test-threads=1`).

**Dependabot.** `.github/dependabot.yml` already updates `github-actions` weekly and `cargo` weekly (limit 5). SHA-pinned actions with `# vX.Y.Z` comments are still updated by Dependabot — it bumps both the SHA and the comment.

**`dtolnay/rust-toolchain` nuance (critical).** The `@stable` / `@1.74` refs are *branches* in the action repo that each set the default toolchain. Pinning to a commit SHA loses that implied toolchain, so any SHA-pinned `dtolnay/rust-toolchain` step **must** add an explicit `with: toolchain: <stable|1.74|…>` input. This applies to every existing `dtolnay/rust-toolchain@stable` (which becomes `@<sha> # vX.Y.Z` + `with: toolchain: stable`, merged with any existing `components:`/`targets:` inputs) and to the new MSRV job (`toolchain: 1.74` or the corrected MSRV).

## Proposed Implementation

Implement as one PR with the workflow/config changes plus the optional test-harness guard. Tackle in dependency order; the MSRV discovery (Step 1) may change downstream values (the toolchain version the MSRV job pins, and the five doc/config sites).

### Step 1 — MSRV job (discover the real MSRV first)

1. **Discover.** Build the workspace on 1.74 and find the true floor:
   - `rustup toolchain install 1.74.0 && cargo +1.74.0 build --all --locked` (and `cargo +1.74.0 build --all --all-features --locked` to match clippy's surface).
   - If it fails, bisect upward (1.75, 1.76, …) to the lowest version that compiles `cargo build --all --locked` cleanly. `matrix-sdk 0.18` and its transitive crypto/transport stack make a value well above 1.74 likely.
2. **If the real MSRV > 1.74**, update all five sites to the discovered value `X.Y`: `Cargo.toml:16`, `clippy.toml`, `README.md:8` (badge URL, both occurrences), `README.md:72`, `README.md:178`, `CONTRIBUTING.md:24`, `CONTRIBUTING.md:74-75`. Add a short note in the README "Prerequisites"/MSRV prose documenting the bump and the reason (matrix-sdk 0.18 floor), since there is no CHANGELOG.
3. **Add the `msrv` job to `ci.yml`** (gated, like the other Rust jobs, on the `Detect Cargo workspace` step):
   ```yaml
   msrv:
     # Compiles the workspace on the declared MSRV so rust-version in
     # Cargo.toml cannot silently drift from what actually builds (issue #315).
     runs-on: ubuntu-latest
     timeout-minutes: 25
     steps:
       - uses: actions/checkout@<sha> # vX.Y.Z
       - name: Detect Cargo workspace
         id: cargo
         run: |
           if [ -f Cargo.toml ]; then echo "present=true" >> "$GITHUB_OUTPUT"; else echo "present=false" >> "$GITHUB_OUTPUT"; fi
       - uses: dtolnay/rust-toolchain@<sha> # vX.Y.Z
         if: steps.cargo.outputs.present == 'true'
         with:
           toolchain: "1.74" # keep in lockstep with Cargo.toml rust-version / clippy.toml
       - uses: Swatinem/rust-cache@<sha> # vX.Y.Z
         if: steps.cargo.outputs.present == 'true'
       - name: cargo build (MSRV)
         if: steps.cargo.outputs.present == 'true'
         run: cargo build --all --locked
   ```
   - **Build, not test, by default.** Dev-dependencies (test-only) frequently require a newer Rust than the crate, so a full `cargo test --all` on the MSRV toolchain can fail for reasons unrelated to the shipped MSRV. Build the workspace (`cargo build --all --locked`). Optionally add `cargo test --all --no-run --locked` to compile (not run) tests; if dev-deps break that, drop it and note why in a comment. Do **not** run `clippy` on the MSRV toolchain (clippy lints differ across versions).
   - Pin the `toolchain:` string to the **same** value as `Cargo.toml`/`clippy.toml` and reference that in a comment so the three stay in lockstep.

### Step 2 — `--locked` on every cargo invocation

Add `--locked` to each invocation listed in *Relevant Repository Context* (skip `cargo fmt --check`). Examples:
- `cargo clippy --all-targets --all-features --locked -- -D warnings`
- `cargo build --all --locked`
- `cargo test --all --locked`
- `cargo build --release --locked -p mx-agent-cli`
- `cargo clippy -p mx-agent-ipc --all-targets --locked -- -D warnings`
- `cargo test -p mx-agent-ipc --locked`
- `cargo test -p mx-agent-sandbox --locked`
- `cargo test -p mx-agent-daemon --test task_orchestration_e2e --locked sandbox_policy_settings_flow_through_task_orchestration`
- In `scripts/matrix_integration_test.sh`: `cargo build -p mx-agent-cli --bin mx-agent --locked` and `cargo test -p mx-agent-daemon --test matrix_integration --locked -- --ignored --nocapture --test-threads=1` (note `--locked` **before** `--`).

Before committing, run `cargo build --all --locked` locally; if it errors with "lock file needs to be updated", regenerate `Cargo.lock` (`cargo update -w` if intended, else `cargo generate-lockfile`) and commit it so the lock matches `Cargo.toml`.

### Step 3 — Pin all actions by commit SHA

For every `uses:` in all workflow files (existing five + new `audit.yml`), resolve the immutable 40-hex commit SHA for the action's current version and rewrite as `owner/action@<sha> # vX.Y.Z`. Resolution (done in a phase that has GitHub access — e.g. the later implement phase, not this spec phase):
- `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` → for a lightweight tag, `.object.sha`; for an annotated tag, dereference via `gh api repos/<owner>/<repo>/git/tags/<sha> --jq .object.sha`. Prefer the action's documented "pin to SHA" value when published.
- Keep the existing version (`v6`, `v2`, `v2.0.0`, etc.) verbatim in the trailing comment.

Actions to pin (owner/action @ current tag):
| Workflow | Action(s) |
|---|---|
| `ci.yml` | `actions/checkout@v6` (×N), `actions/setup-python@v6`, `pnpm/action-setup@v6`, `actions/setup-node@v6`, `dtolnay/rust-toolchain@stable` (×N), `Swatinem/rust-cache@v2` (×N), `EmbarkStudios/cargo-deny-action@v2` |
| `release.yml` | `actions/checkout@v6`, `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`, `actions/upload-artifact@v7`, `actions/download-artifact@v8`, `softprops/action-gh-release@v3` |
| `project-sync.yml` | `actions/add-to-project@v2.0.0` |
| `wiki-sync.yml` | `actions/checkout@v6` |
| `populate-github.yml` | `actions/checkout@v6`, `actions/setup-python@v6` |
| `audit.yml` (new) | `actions/checkout@v6`, `EmbarkStudios/cargo-deny-action@v2` |

For each `dtolnay/rust-toolchain` step, after switching to the SHA, **add `with: toolchain: stable`** (merging with any existing `components:`/`targets:` inputs) so the pinned commit still selects the right toolchain. The MSRV job uses `toolchain: "1.74"` (or the corrected MSRV).

### Step 4 — Pin the homeserver image by digest

1. Resolve the digest of the current `:latest`:
   - `docker buildx imagetools inspect ghcr.io/matrix-construct/tuwunel:latest` (read the top-level manifest `Digest:`), or `docker pull ghcr.io/matrix-construct/tuwunel:latest && docker inspect --format '{{index .RepoDigests 0}}' ghcr.io/matrix-construct/tuwunel:latest`.
2. Rewrite `dev/matrix/docker-compose.yml:10`:
   ```yaml
   # Pinned by digest for reproducible e2e runs (issue #315). Corresponds to
   # the `:latest` tag as of <YYYY-MM-DD>; bump deliberately (or via Dependabot).
   image: ghcr.io/matrix-construct/tuwunel@sha256:<digest>
   ```
3. *(Recommended, the issue says "consider")* Add a Dependabot entry so the digest gets refreshed:
   ```yaml
   - package-ecosystem: docker-compose   # verify ecosystem name picks up dev/matrix/docker-compose.yml
     directory: /dev/matrix
     schedule:
       interval: weekly
   ```
   Confirm the chosen ecosystem (`docker-compose` vs `docker`) actually scans `docker-compose.yml`; if neither does in this account, drop this sub-step and note it as manual.
4. Verify by running `scripts/matrix_integration_test.sh --teardown` locally (Docker required) — the suite must pass against the digest-pinned image.

### Step 5 — `timeout-minutes` on every job

Add a `timeout-minutes` to each job. Suggested values (tune to observed durations; keep headroom):
- `ci.yml`: `docs` 10, `shell` 10, `adw` 10, `adw-sdlc` 15, `rust` 30, `rust-macos` 25, `sandbox-linux` 20, `cargo-deny` 15, `matrix-integration` 35, `msrv` (new) 25.
- `release.yml`: `build` 30, `release` 15.
- `project-sync.yml`: `add-to-project` 10.
- `wiki-sync.yml`: `sync` 10.
- `populate-github.yml`: `populate` 10.
- `audit.yml` (new): `audit` 15.

### Step 6 — Scheduled advisories workflow (`audit.yml`)

New file `.github/workflows/audit.yml`:
```yaml
name: audit

# Re-run the RustSec advisory check on a schedule so a newly published
# advisory against an already-locked dependency surfaces without waiting for
# the next push (issue #315). The push/PR cargo-deny job in ci.yml still runs
# the full `check advisories bans licenses sources` gate on every change.
on:
  schedule:
    - cron: "17 6 * * 1" # Mondays 06:17 UTC (avoid the high-load top-of-hour)
  workflow_dispatch: {}

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@<sha> # vX.Y.Z
      - uses: EmbarkStudios/cargo-deny-action@<sha> # vX.Y.Z
        with:
          command: check advisories
```
- Scope the scheduled run to `advisories` (licenses/sources/bans don't change without a code change, which the push/PR gate already covers).
- Keep `permissions: contents: read` (least privilege; no write needed).
- Verify with **one manual `workflow_dispatch`** after merge (acceptance criterion).

### Step 7 — Static regression guard (`scripts/test_ci_yml.sh`)

Add a pure-bash checker modeled on `scripts/test_release_yml.sh`, run in the `shell` CI job and covered by the existing `shellcheck scripts/*.sh` step. Assertions:
- **No mutable action refs:** every `uses:` line in all `.github/workflows/*.yml` matches `@[0-9a-f]{40}` (40-hex SHA). Flag any `@v…`/`@<branch>` ref. (Iterate over all workflow files, not just one.)
- **`--locked` coverage:** every `cargo build`/`cargo test`/`cargo clippy` line in `ci.yml` (and `scripts/matrix_integration_test.sh`) contains `--locked`. (Exclude `cargo fmt`.)
- **Timeouts:** every job has a `timeout-minutes:` (count `runs-on:` occurrences vs `timeout-minutes:` occurrences per file, or assert each job block contains one).
- **MSRV job present** in `ci.yml` and its `toolchain:` matches the `rust-version` in `Cargo.toml` / `msrv` in `clippy.toml` (grep all three and compare).
- **Scheduled audit present:** `audit.yml` exists, has `schedule:`/`cron:` and `workflow_dispatch`, and runs `check advisories`.
Wire it into the `shell` job alongside `test_release_yml.sh`. Keep it ShellCheck-clean. Use `set -euo pipefail` and the same `ok`/`not_ok` + summary structure as `test_release_yml.sh`.

### Step 8 *(Recommended)* — In-harness single-thread guard

Add a `#[forbid(unsafe_code)]`-compatible (no `unsafe`) global guard to `crates/mx-agent-daemon/tests/matrix_integration.rs`:
- A module-level `static LIVE_TEST_RUNNING: AtomicBool = AtomicBool::new(false);` (the file already imports `AtomicBool`/`Ordering`).
- A helper returning an RAII guard:
  ```rust
  /// Trips when two live integration tests overlap. The suite mutates
  /// process-global env (`MX_AGENT_DATA_DIR`, `MX_AGENT_CONFIG_DIR`) via 59
  /// `set_var` calls and is correct only single-threaded, so it MUST run via
  /// `scripts/matrix_integration_test.sh` (which passes `--test-threads=1`).
  #[must_use]
  fn enter_single_threaded_section() -> SingleThreadGuard {
      if LIVE_TEST_RUNNING.swap(true, Ordering::SeqCst) {
          panic!(
              "two live integration tests are running concurrently; this suite \
               mutates process-global env and MUST run single-threaded. Run it \
               via scripts/matrix_integration_test.sh (which passes \
               --test-threads=1), not a bare `cargo test -- --ignored`."
          );
      }
      SingleThreadGuard
  }
  struct SingleThreadGuard;
  impl Drop for SingleThreadGuard {
      fn drop(&mut self) { LIVE_TEST_RUNNING.store(false, Ordering::SeqCst); }
  }
  ```
- Add `let _serial = enter_single_threaded_section();` as the **first** statement of every `#[ignore]` live test (or at minimum every test that calls `set_var`). The guard releases on drop (including during panic unwind, so a failing test does not poison later runs).
- **Unit-level coverage** (a normal `#[test]`, *not* `#[ignore]`, so it runs in `cargo test --all` and never alongside the ignored live tests):
  ```rust
  #[test]
  fn single_thread_guard_trips_on_overlap() {
      let held = enter_single_threaded_section(); // first acquisition holds the flag
      let res = std::panic::catch_unwind(|| { let _g = enter_single_threaded_section(); });
      assert!(res.is_err(), "second concurrent acquisition must panic");
      drop(held);
      // flag is released; a fresh acquisition now succeeds
      let _g = enter_single_threaded_section();
  }
  ```
  `catch_unwind` works because panics unwind by default; silence the expected panic's backtrace noise via a scoped `std::panic::set_hook`/`take_hook` if desired.
- Confirm the full live suite still passes under `--test-threads=1` (the guard is acquired and released serially, so it never trips in the real run).

## Affected Files / Crates / Modules

**Read:**
- `Cargo.toml`, `Cargo.lock`, `clippy.toml`, `rustfmt.toml`
- `README.md` (badge + prereqs + MSRV prose), `CONTRIBUTING.md` (MSRV prose)
- `scripts/test_release_yml.sh` (pattern), `scripts/matrix_integration_test.sh`, `scripts/matrix_dev.sh`
- `crates/mx-agent-daemon/tests/matrix_integration.rs`
- `.github/dependabot.yml`, `deny.toml`, `dev/matrix/docker-compose.yml`, `dev/matrix/README.md`

**Modify:**
- `.github/workflows/ci.yml` — add `msrv` job; `--locked`; SHA-pin all `uses:` (+ `toolchain:` inputs on `dtolnay/rust-toolchain`); `timeout-minutes` on every job; add `test_ci_yml.sh` to the `shell` job.
- `.github/workflows/release.yml` — SHA-pin all `uses:` (+ `toolchain: stable`); `timeout-minutes` on `build` and `release`. (Release build already has `--locked`.)
- `.github/workflows/project-sync.yml`, `.github/workflows/wiki-sync.yml`, `.github/workflows/populate-github.yml` — SHA-pin `uses:`; `timeout-minutes`.
- `.github/workflows/audit.yml` — **new** scheduled advisories workflow.
- `.github/dependabot.yml` — *(optional)* add docker(-compose) ecosystem for the homeserver image.
- `dev/matrix/docker-compose.yml` — digest-pin the tuwunel image.
- `Cargo.toml`, `clippy.toml`, `README.md`, `CONTRIBUTING.md` — **only if** the MSRV proves > 1.74; update all five sites in lockstep.
- `Cargo.lock` — regenerate/commit only if `--locked` reveals it is stale.
- `scripts/matrix_integration_test.sh` — `--locked` on both cargo invocations.
- `scripts/test_ci_yml.sh` — **new** static regression guard.
- `crates/mx-agent-daemon/tests/matrix_integration.rs` — *(recommended)* single-thread guard + unit test + per-test acquisition.

## CLI / API Changes

None. No command-line surface, public Rust API, IPC method, or wire protocol changes. The single-thread guard is test-only (`tests/`, not part of any crate's public API) and adds no `pub` items to shipped code.

## Data Model / Protocol Changes

None. No event schema, persistence format, policy structure, or serialization changes. `deny.toml` is unchanged. `Cargo.lock` may be regenerated but its *format* is unchanged.

## Security Considerations

- **Supply-chain integrity (the point of this work):** SHA-pinning every action removes the tag-mutation / retag-attack vector; digest-pinning the homeserver image makes e2e runs reproducible; `--locked` ensures CI/release build exactly the cargo-deny-audited graph; the scheduled audit shrinks the window between an advisory's publication and its detection.
- **No secrets in logs:** workflow edits must not echo `MATRIX_REGISTRATION_TOKEN` or anything from `dev/matrix/.env` into job logs. The new `audit.yml` touches no secrets and uses `permissions: contents: read`. The digest-pin and `--locked` changes add no logging. Preserve the existing redaction posture; do not add `set -x`/`--verbose` that could surface env in the live harness.
- **Least privilege:** `audit.yml` declares `permissions: contents: read`. Do not widen any existing job's permissions. The release workflow's per-job `contents: read`/`write` split (enforced by `test_release_yml.sh`) is preserved.
- **MSRV as a security-relevant invariant:** the issue treats MSRV correctness as a constraint — either 1.74 holds, or the corrected value is both declared (`Cargo.toml` + `clippy.toml` + docs) and enforced by the new CI job from then on.
- **No `unsafe`:** the harness guard uses `AtomicBool` + RAII `Drop` only; it must compile under the workspace's `unsafe_code = "forbid"`.
- **Daemon/CLI separation, signing/trust, deny-by-default policy, Unix-only:** untouched. No runtime code paths change; the coding agent still never sees Matrix tokens or device keys; room membership still does not imply execution permission; privileged requests stay Ed25519-signed and policy-checked.

## Testing Plan

- **MSRV job (CI):** the new `msrv` job is green at the declared `rust-version`. Sanity-check the negative case locally: temporarily use an API newer than the MSRV in a throwaway branch and confirm `cargo +<msrv> build --all --locked` fails (do not commit).
- **`--locked` (CI):** confirm `cargo build --all --locked` / `cargo test --all --locked` pass with the committed `Cargo.lock`; confirm a deliberately stale lock fails `--locked` locally (then revert).
- **Static guard (`scripts/test_ci_yml.sh`):** run it locally and in the `shell` job; it must pass on the hardened workflows and fail if a mutable ref / missing `--locked` / missing `timeout-minutes` is reintroduced. Add a quick self-check by hand (e.g. temporarily revert one SHA to `@v6` and confirm the guard fails). Keep it ShellCheck-clean (the `shell` job runs `shellcheck scripts/*.sh`).
- **Scheduled audit:** trigger `audit.yml` once via `workflow_dispatch` and confirm it runs `cargo deny check advisories` green.
- **Homeserver digest:** run `scripts/matrix_integration_test.sh --teardown` against the digest-pinned image; the full live suite passes.
- **Single-thread guard unit test:** `cargo test -p mx-agent-daemon --test matrix_integration single_thread_guard_trips_on_overlap` passes (guard trips on overlap, releases after). The full `#[ignore]` suite still passes under `--test-threads=1`.
- **Regression baseline:** `cargo fmt --check`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, `cargo build --all --locked`, `cargo test --all --locked` stay green on Linux; `cargo clippy -p mx-agent-ipc … --locked` and `cargo test -p mx-agent-ipc --locked` stay green on the macOS job.

## Documentation Updates

- **README.md / CONTRIBUTING.md:** update the MSRV badge and all prose sites **only if** the MSRV is corrected above 1.74; document the bump and reason (no CHANGELOG exists). If 1.74 holds, no doc change to MSRV text.
- **`dev/matrix/docker-compose.yml`:** inline comment recording the digest↔tag/date correspondence and that it is pinned for reproducibility (issue #315). Optionally note the digest-pin in `dev/matrix/README.md` so contributors know to bump it deliberately.
- **CI/dev docs:** if a "Development" section documents CI jobs, mention the new `msrv` job and `audit.yml`. (No status-table/wiki change is strictly required; keep edits minimal and accurate — do not imply unimplemented behavior.)
- **`scripts/test_ci_yml.sh`:** self-documenting header comment matching the `test_release_yml.sh` style (purpose, usage, exit codes).

## Risks and Open Questions

1. **Real MSRV likely > 1.74.** If `matrix-sdk 0.18` requires a substantially newer Rust, the MSRV bump cascades into all five doc/config sites and the badge. **Decision needed at implementation time:** what is the discovered floor, and is bumping `rust-version` to it acceptable (it is — that's the issue's explicit fallback). The bump should be the *minimum* that builds, not "latest stable".
2. **MSRV: build vs. test.** Running `cargo test --all` on the MSRV toolchain may fail on dev-dependency MSRVs unrelated to shipped code. Recommendation: build-only (optionally `test --no-run`). Confirm which is achievable; document the choice in the job comment.
3. **`--locked` requires a current `Cargo.lock`.** If the committed lock is stale relative to `Cargo.toml`, `--locked` will fail CI immediately. Regenerate and commit the lock in the same PR; this is expected, not a blocker.
4. **`dtolnay/rust-toolchain` SHA pin needs `toolchain:` inputs.** Easy to miss — a SHA pin without `with: toolchain:` silently changes which toolchain is selected. The static guard should ideally assert every `dtolnay/rust-toolchain` step carries a `toolchain:` input (nice-to-have).
5. **Dependabot docker(-compose) ecosystem support.** Whether Dependabot updates the `image:` digest in `docker-compose.yml` depends on the ecosystem name and account support. Treat the Dependabot docker entry as best-effort; if it doesn't pick up the file, document the digest bump as a manual step instead.
6. **SHA resolution needs GitHub access.** This spec phase has none; SHA/digest resolution happens in the later implement phase. The implementer must dereference annotated tags correctly (tag object → commit) rather than pinning the tag-object SHA.
7. **Guard coverage is per-test.** The single-thread guard only detects an overlap when *both* concurrent tests acquire it; full protection requires adding the acquisition line to every `#[ignore]` test. Adding it to all live tests is mechanical but touches many functions — acceptable, and the highest-value (env-mutating) tests must be covered at minimum.
8. **Cron timing.** Use a non-midnight, off-the-hour minute (e.g. `17 6 * * 1`) per GitHub's guidance to avoid the high-contention top-of-hour scheduling delays.

## Implementation Checklist

1. [ ] Install 1.74.0; run `cargo +1.74.0 build --all --locked` (and `--all-features`). Record whether it compiles.
2. [ ] If it fails, bisect upward to the lowest building version `X.Y`; update `Cargo.toml:16`, `clippy.toml`, `README.md:8` (badge ×2), `README.md:72`, `README.md:178`, `CONTRIBUTING.md:24`, `CONTRIBUTING.md:74-75`; add an MSRV-bump note to the README. Keep the three machine-read sites (`rust-version`, `clippy msrv`, MSRV-job `toolchain`) identical.
3. [ ] Add the `msrv` job to `ci.yml` (build-only, `--locked`, `timeout-minutes: 25`, `toolchain:` = declared MSRV, SHA-pinned actions).
4. [ ] Add `--locked` to every `cargo build`/`test`/`clippy` in `ci.yml` and to both cargo calls in `scripts/matrix_integration_test.sh` (`--locked` before `--` for the test). Skip `cargo fmt --check`.
5. [ ] Run `cargo build --all --locked` locally; regenerate/commit `Cargo.lock` if it reports the lock is stale.
6. [ ] Resolve commit SHAs for every action in `ci.yml`, `release.yml`, `project-sync.yml`, `wiki-sync.yml`, `populate-github.yml`, and the new `audit.yml`; rewrite each `uses:` as `owner/action@<40-hex> # vX.Y.Z`.
7. [ ] For every `dtolnay/rust-toolchain` step, add `with: toolchain: <stable|MSRV>` (merge with existing `components:`/`targets:`).
8. [ ] Add `timeout-minutes` to every job in all six workflows (values per *Step 5*).
9. [ ] Create `.github/workflows/audit.yml` (weekly cron `17 6 * * 1` + `workflow_dispatch`, `permissions: contents: read`, `cargo deny check advisories`, SHA-pinned actions, `timeout-minutes: 15`).
10. [ ] Resolve the tuwunel `:latest` digest; rewrite `dev/matrix/docker-compose.yml:10` to `@sha256:<digest>` with a tag/date comment.
11. [ ] *(Optional)* Add a Dependabot docker(-compose) entry for `/dev/matrix`; verify it scans the compose file, else note the manual bump.
12. [ ] Create `scripts/test_ci_yml.sh` (SHA-pin, `--locked`, `timeout-minutes`, MSRV-job present + version-lockstep, audit-workflow present); wire it into the `shell` job; ensure ShellCheck-clean.
13. [ ] *(Recommended)* Add the single-thread guard (`AtomicBool` + RAII, no `unsafe`) to `matrix_integration.rs`, acquire it at the top of each `#[ignore]` live test, and add the `single_thread_guard_trips_on_overlap` unit test.
14. [ ] Run locally: `cargo fmt --check`; `cargo clippy --all-targets --all-features --locked -- -D warnings`; `cargo build --all --locked`; `cargo test --all --locked`; `bash scripts/test_release_yml.sh`; `bash scripts/test_ci_yml.sh`; `shellcheck scripts/*.sh`.
15. [ ] Run `scripts/matrix_integration_test.sh --teardown` against the digest-pinned image; confirm the full live suite passes under `--test-threads=1`.
16. [ ] After merge: trigger `audit.yml` once via `workflow_dispatch` and confirm green; confirm a Dependabot actions PR (when next raised) still updates a SHA-pinned `uses:` correctly.
