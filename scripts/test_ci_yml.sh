#!/usr/bin/env bash
# test_ci_yml.sh — static acceptance tests for the CI/supply-chain hardening
# invariants from issue #315. Mirrors scripts/test_release_yml.sh: a pure-bash,
# ShellCheck-clean checker that greps the repo for structural guarantees so they
# cannot silently regress.
#
# Asserts:
#   - Every `uses:` across .github/workflows/*.yml is a full 40-hex commit SHA
#     (no moving @vN tags or @branch refs).
#   - Every dtolnay/rust-toolchain step carries an explicit `toolchain:` input
#     (a SHA pin drops the @stable/@1.93 branch's implied default).
#   - Every CI/harness `cargo build|test|clippy` carries --locked (cargo fmt
#     does not resolve deps and is exempt).
#   - Every job in every workflow declares a `timeout-minutes:`.
#   - The `msrv` job exists and its `toolchain:` matches Cargo.toml rust-version
#     and clippy.toml msrv (the three machine-read MSRV sites stay in lockstep).
#   - The scheduled advisories workflow (audit.yml) exists with schedule/cron +
#     workflow_dispatch and runs `check advisories`.
#
# Usage: scripts/test_ci_yml.sh
# Exit:  0 = all tests passed, 1 = one or more tests failed.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
wf_dir="$repo_root/.github/workflows"
ci="$wf_dir/ci.yml"
audit="$wf_dir/audit.yml"
cargo_toml="$repo_root/Cargo.toml"
clippy_toml="$repo_root/clippy.toml"
harness="$repo_root/scripts/matrix_integration_test.sh"

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

# Guard: the workflow directory must exist or every assertion is vacuous.
if [ ! -d "$wf_dir" ]; then
  echo "FATAL: $wf_dir not found" >&2
  exit 1
fi

# ─── Every action `uses:` is a 40-hex commit SHA ─────────────────────────────
# A mutable @vN tag or @branch ref lets a compromised/retagged release flow into
# CI. Each `uses:` key line must carry `@<40-hex>` (issue #315).

mutable=$(grep -nE '^[[:space:]]*(- )?uses:[[:space:]]' "$wf_dir"/*.yml \
  | grep -vE '@[0-9a-f]{40}' || true)
if [ -z "$mutable" ]; then
  ok "every action 'uses:' is pinned to a 40-hex commit SHA"
else
  not_ok "mutable (non-SHA) action ref(s) found in workflows:"
  echo "$mutable" >&2
fi

# ─── Every dtolnay/rust-toolchain step has a toolchain: input ─────────────────
# Pinning the action to a SHA loses the @stable/@1.93 branch's implied default
# toolchain, so each step must name it explicitly. There must be at least as
# many `toolchain:` inputs as dtolnay/rust-toolchain steps.

# grep -c reports a per-file count over multiple files, so total via wc -l.
dtolnay_steps=$( { grep -hE 'uses:[[:space:]]*dtolnay/rust-toolchain@' "$wf_dir"/*.yml || true; } | wc -l | tr -d '[:space:]')
toolchain_inputs=$( { grep -hE '^[[:space:]]*toolchain:' "$wf_dir"/*.yml || true; } | wc -l | tr -d '[:space:]')
if [ "$toolchain_inputs" -ge "$dtolnay_steps" ] && [ "$dtolnay_steps" -gt 0 ]; then
  ok "every dtolnay/rust-toolchain step carries a toolchain: input ($dtolnay_steps step(s), $toolchain_inputs input(s))"
else
  not_ok "dtolnay/rust-toolchain steps ($dtolnay_steps) outnumber toolchain: inputs ($toolchain_inputs) — a SHA pin without toolchain: silently changes the toolchain"
fi

# ─── --locked on every CI/harness cargo build|test|clippy ────────────────────
# An out-of-date Cargo.lock must fail CI rather than silently re-resolve to a
# graph cargo-deny never audited. cargo fmt resolves nothing and is exempt;
# comment lines (e.g. prose mentioning `cargo test`) are filtered out.

check_locked() {
  local file="$1" label="$2" offenders
  offenders=$(grep -nE 'cargo (build|test|clippy)' "$file" \
    | grep -v 'cargo fmt' \
    | grep -vE '^[0-9]+:[[:space:]]*#' \
    | grep -vE '^[0-9]+:[[:space:]]*(- )?name:' \
    | grep -v -- '--locked' || true)
  if [ -z "$offenders" ]; then
    ok "$label: every cargo build|test|clippy carries --locked"
  else
    not_ok "$label: cargo invocation(s) missing --locked:"
    echo "$offenders" >&2
  fi
}

check_locked "$ci" "ci.yml"
check_locked "$harness" "scripts/matrix_integration_test.sh"

# ─── Every job declares a timeout-minutes ────────────────────────────────────
# A hung job otherwise holds a runner for GitHub's 360-minute default. One
# runs-on: per job, so the timeout-minutes: count must equal the runs-on: count
# in every workflow file.

for f in "$wf_dir"/*.yml; do
  runs=$(grep -cE '^[[:space:]]*runs-on:' "$f" || true)
  timeouts=$(grep -cE '^[[:space:]]*timeout-minutes:' "$f" || true)
  base=$(basename "$f")
  if [ "$runs" -eq "$timeouts" ] && [ "$runs" -gt 0 ]; then
    ok "$base: every job has a timeout-minutes ($runs job(s))"
  else
    not_ok "$base: $runs job(s) but $timeouts timeout-minutes — every job needs one"
  fi
done

# ─── MSRV job present and version-locked to Cargo.toml / clippy.toml ──────────
# The msrv job's quoted numeric toolchain (e.g. toolchain: "1.93") must match
# rust-version in Cargo.toml and msrv in clippy.toml so the three machine-read
# sites cannot drift.

if grep -qE '^[[:space:]]*msrv:' "$ci"; then
  ok "ci.yml declares an 'msrv' job"
else
  not_ok "ci.yml has no 'msrv' job — the declared MSRV is never built"
fi

cargo_msrv=$(grep -E '^[[:space:]]*rust-version[[:space:]]*=' "$cargo_toml" \
  | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
clippy_msrv=$(grep -E '^[[:space:]]*msrv[[:space:]]*=' "$clippy_toml" \
  | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
job_msrv=$(grep -E '^[[:space:]]*toolchain:[[:space:]]*"[0-9]' "$ci" \
  | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)

if [ -n "$cargo_msrv" ] && [ "$cargo_msrv" = "$clippy_msrv" ] && [ "$cargo_msrv" = "$job_msrv" ]; then
  ok "MSRV is in lockstep (Cargo.toml=$cargo_msrv, clippy.toml=$clippy_msrv, msrv job=$job_msrv)"
else
  not_ok "MSRV sites disagree (Cargo.toml='$cargo_msrv' clippy.toml='$clippy_msrv' msrv job='$job_msrv')"
fi

# ─── Scheduled advisories workflow present ───────────────────────────────────
# audit.yml re-runs the RustSec advisory check on a cron so a newly published
# advisory surfaces without waiting for the next push.

if [ -f "$audit" ] \
  && grep -q 'schedule:' "$audit" \
  && grep -q 'cron:' "$audit" \
  && grep -q 'workflow_dispatch' "$audit" \
  && grep -q 'check advisories' "$audit"; then
  ok "audit.yml runs 'check advisories' on a schedule + workflow_dispatch"
else
  not_ok "audit.yml missing or incomplete (need schedule/cron + workflow_dispatch + 'check advisories')"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "Results: $pass passed, $fail failed"
if [ "$fail" -gt 0 ]; then
  exit 1
fi
