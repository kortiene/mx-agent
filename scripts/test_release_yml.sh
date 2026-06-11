#!/usr/bin/env bash
# test_release_yml.sh — static acceptance tests for .github/workflows/release.yml
#
# Validates the structural fixes from issue #303:
#   - Dead Windows packaging branches (zip/exe/7z) removed
#   - Release build uses --locked
#   - Retired macos-13 runner replaced by a schedulable Intel image
#   - permissions: contents: write confined to the publish job only
#   - Header comment reflects the Unix-only, "Windows dropped" stance
#   - fail_on_unmatched_files: true retained in the publish step
#
# Usage: scripts/test_release_yml.sh
# Exit:  0 = all tests passed, 1 = one or more tests failed.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
workflow="$repo_root/.github/workflows/release.yml"

pass=0
fail=0

ok() {
  echo "PASS: $1"
  pass=$((pass + 1))
}

not_ok() {
  echo "FAIL: $1" >&2
  fail=$((fail + 1))
}

# Guard: the file must exist or every assertion below is vacuously wrong.
if [ ! -f "$workflow" ]; then
  echo "FATAL: $workflow not found" >&2
  exit 1
fi

# ─── Dead Windows packaging branches ─────────────────────────────────────────
# grep -n 'zip\|\.exe\|7z' must return nothing; any match means a Windows
# vestige survived the cleanup (issue #303 acceptance criterion).

dead_windows=$(grep -nE '(\.zip|\.exe|7z)' "$workflow" || true)
if [ -z "$dead_windows" ]; then
  ok "no zip/.exe/7z references remain in release.yml"
else
  not_ok "dead Windows packaging remnants found in release.yml:"
  echo "$dead_windows" >&2
fi

# ─── --locked on the release build ───────────────────────────────────────────
# The cargo build step must carry --locked so shipped binaries match the
# cargo-deny-audited Cargo.lock.

if grep -qE 'cargo build.*--locked' "$workflow"; then
  ok "release build step carries --locked"
else
  not_ok "release build step is missing --locked (supply-chain gap)"
fi

# ─── Retired macos-13 runner not used as an active os: value ─────────────────
# macos-13 was retired and never schedules; both v0.1.0 and v0.2.0 hung 24h.
# Comments may legitimately reference it to document the history; only the
# active `os: macos-13` YAML assignment is prohibited.

active_macos13=$(grep -E '^\s+os:\s+macos-13\b' "$workflow" || true)
if [ -z "$active_macos13" ]; then
  ok "retired macos-13 runner is not an active os: assignment"
else
  not_ok "macos-13 is still used as an active os: value — the Intel build will hang (issue #303)"
  echo "$active_macos13" >&2
fi

# ─── Schedulable Intel runner present ────────────────────────────────────────
# The x86_64-apple-darwin target must build on a native Intel image so that
# gen-cli-artifacts.sh can execute the freshly built Intel binary.

if grep -qE 'macos-[0-9]+-intel|macos-.*intel' "$workflow"; then
  ok "a native Intel macOS runner is configured for x86_64-apple-darwin"
else
  not_ok "no native Intel macOS runner found — x86_64-apple-darwin build will not schedule"
fi

# ─── No top-level permissions: contents: write ───────────────────────────────
# Workflow-level write grants all jobs (including build) write access;
# only the publish (release) job should hold contents: write.
#
# The check looks for `contents: write` appearing before the `jobs:` line,
# which is where a top-level permissions block would live.

jobs_line=$(grep -n '^jobs:' "$workflow" | head -1 | cut -d: -f1)
if [ -n "$jobs_line" ]; then
  top_level_write=$(head -n "$jobs_line" "$workflow" | grep -E 'contents:\s*write' || true)
  if [ -z "$top_level_write" ]; then
    ok "no top-level 'contents: write' (least-privilege check)"
  else
    not_ok "workflow-level 'contents: write' found — build jobs get unnecessary write access:"
    echo "$top_level_write" >&2
  fi
else
  not_ok "could not locate 'jobs:' line in release.yml to check top-level permissions"
fi

# ─── Build job has contents: read ────────────────────────────────────────────

if grep -qE 'contents:\s*read' "$workflow"; then
  ok "build job declares 'contents: read' (checkout only)"
else
  not_ok "no 'contents: read' found — build job permissions not scoped to read"
fi

# ─── Release (publish) job has contents: write ───────────────────────────────

if grep -qE 'contents:\s*write' "$workflow"; then
  ok "publish job retains 'contents: write' for softprops/action-gh-release"
else
  not_ok "no 'contents: write' found — publish job cannot create the GitHub Release"
fi

# ─── Header comment: Windows "dropped", not "future work" ────────────────────
# The old comment said Windows was "future work"; it must now say Windows was
# "intentionally dropped". The phrase "(not future work)" is acceptable (it's
# the negation), but a bare "future work" claim would be wrong.
# Check the positive: "intentionally dropped" must appear.

if grep -iq 'intentionally dropped' "$workflow"; then
  ok "header states Windows was 'intentionally dropped' (matches README.md:60)"
else
  not_ok "header does not say 'intentionally dropped' — update to match README.md:60"
fi

# A bare positive "future work" claim (without negation) would reintroduce the
# old bad wording. Filter out any negated form "(not future work)" and flag
# whatever remains.
bare_future_work=$(grep -i 'future work' "$workflow" | grep -iv 'not future work' || true)
if [ -z "$bare_future_work" ]; then
  ok "no positive 'future work' claim for Windows found in release.yml"
else
  not_ok "release.yml contains a positive 'future work' claim — update to 'intentionally dropped':"
  echo "$bare_future_work" >&2
fi

# ─── fail_on_unmatched_files: true retained ───────────────────────────────────
# This setting must stay so an accidental glob regression (e.g. a *.zip creep)
# causes the publish step to fail rather than silently succeed with fewer files.

if grep -q 'fail_on_unmatched_files: true' "$workflow"; then
  ok "fail_on_unmatched_files: true is still present in the publish step"
else
  not_ok "fail_on_unmatched_files: true was removed — publish may silently skip files"
fi

# ─── No artifacts/*.zip in the publish files list ─────────────────────────────
# After removing the Windows target there are no zip archives; the glob must
# not appear in the publish files list or fail_on_unmatched_files would abort.

if ! grep -q 'artifacts/\*\.zip' "$workflow"; then
  ok "artifacts/*.zip glob removed from publish files list"
else
  not_ok "artifacts/*.zip glob still in publish files — will fail with fail_on_unmatched_files: true"
fi

# ─── Three build targets remain ───────────────────────────────────────────────
# The matrix must still cover: x86_64-unknown-linux-gnu, x86_64-apple-darwin,
# aarch64-apple-darwin. The grep counts unique target: entries in the matrix.

linux_target=$(grep -c 'x86_64-unknown-linux-gnu' "$workflow" || true)
intel_mac=$(grep -c 'x86_64-apple-darwin' "$workflow" || true)
arm_mac=$(grep -c 'aarch64-apple-darwin' "$workflow" || true)

if [ "$linux_target" -ge 1 ] && [ "$intel_mac" -ge 1 ] && [ "$arm_mac" -ge 1 ]; then
  ok "all three build targets present (Linux x86_64, macOS Intel, macOS arm64)"
else
  not_ok "one or more build targets missing (linux=$linux_target intel_mac=$intel_mac arm_mac=$arm_mac)"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "Results: $pass passed, $fail failed"
if [ "$fail" -gt 0 ]; then
  exit 1
fi
