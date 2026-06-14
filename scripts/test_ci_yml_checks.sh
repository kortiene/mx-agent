#!/usr/bin/env bash
# test_ci_yml_checks.sh — fixture-based regression tests for test_ci_yml.sh
#
# Verifies that each invariant check in test_ci_yml.sh:
#   1. Fires (exits 1) on a fixture that violates exactly that invariant.
#   2. Passes (exits 0) on a fully compliant fixture.
#   3. The real project repository files pass without regression.
#
# Mirrors the pattern used by test_check_doc_claims.sh.
#
# Usage: scripts/test_ci_yml_checks.sh
# Exit:  0 = all tests passed, 1 = one or more tests failed.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
sut="$script_dir/test_ci_yml.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

pass=0
fail=0

ok()     { echo "PASS: $1"; pass=$((pass + 1)); }
not_ok() { echo "FAIL: $1" >&2; fail=$((fail + 1)); }

# ─── fixture infrastructure ───────────────────────────────────────────────────

# Create a fixture root and copy the SUT into scripts/ so dirname "$0"
# resolves to <froot>/scripts and repo_root resolves to <froot>.
setup_fixture() {
  local name="$1"
  local froot="$tmpdir/$name"
  mkdir -p "$froot/.github/workflows" "$froot/scripts"
  cp "$sut" "$froot/scripts/test_ci_yml.sh"
  echo "$froot"
}

# Run the SUT from within the fixture root (captures stdout+stderr).
run_sut() {
  local froot="$1"
  (
    cd "$froot"
    bash scripts/test_ci_yml.sh 2>&1
  )
}

# ── shared support files ──────────────────────────────────────────────────────

write_cargo_toml() {
  cat > "$1/Cargo.toml" <<'EOF'
[workspace]
[workspace.package]
rust-version = "1.93"
EOF
}

write_clippy_toml() {
  cat > "$1/clippy.toml" <<'EOF'
msrv = "1.93"
EOF
}

write_harness_locked() {
  cat > "$1/scripts/matrix_integration_test.sh" <<'EOF'
#!/usr/bin/env bash
cargo test -p mx-agent-daemon --test matrix_integration --locked -- --ignored --test-threads=1
EOF
}

write_audit_yml() {
  cat > "$1/.github/workflows/audit.yml" <<'EOF'
name: audit
on:
  schedule:
    - cron: "17 6 * * 1"
  workflow_dispatch: {}
jobs:
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: EmbarkStudios/cargo-deny-action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v2
        with:
          command: check advisories
EOF
}

# A fully-compliant minimal ci.yml: SHA-pinned actions, explicit toolchain:
# inputs, --locked on every cargo build/test/clippy, timeout-minutes on both
# jobs, and an msrv job with a quoted numeric toolchain matching the MSRV files.
write_ci_yml_valid() {
  cat > "$1/.github/workflows/ci.yml" <<'EOF'
name: ci
on:
  pull_request:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # master
        with:
          toolchain: stable
      - run: cargo build --locked
      - run: cargo test --locked
      - run: cargo clippy --all-targets --locked
  msrv:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # master
        with:
          toolchain: "1.93"
      - run: cargo build --locked
EOF
}

# ─── Test 1: fully valid fixture exits 0 ──────────────────────────────────────

t="$(setup_fixture t_valid)"
write_ci_yml_valid "$t"
write_audit_yml "$t"
write_cargo_toml "$t"
write_clippy_toml "$t"
write_harness_locked "$t"

exit_code=0
run_sut "$t" > /dev/null || exit_code=$?
if [ "$exit_code" -eq 0 ]; then
  ok "fully valid fixture exits 0"
else
  not_ok "fully valid fixture should exit 0 (got $exit_code)"
fi

# ─── Test 2: mutable action ref detected ──────────────────────────────────────
# actions/checkout@v6 is a moving tag, not a 40-hex SHA → must trigger exit 1.

t="$(setup_fixture t_mutable_ref)"
write_audit_yml "$t"
write_cargo_toml "$t"
write_clippy_toml "$t"
write_harness_locked "$t"

cat > "$t/.github/workflows/ci.yml" <<'EOF'
name: ci
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v6
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # master
        with:
          toolchain: stable
      - run: cargo build --locked
      - run: cargo test --locked
      - run: cargo clippy --locked
  msrv:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # master
        with:
          toolchain: "1.93"
      - run: cargo build --locked
EOF

exit_code=0
run_sut "$t" > /dev/null || exit_code=$?
if [ "$exit_code" -ne 0 ]; then
  ok "mutable action ref (@v6 tag) triggers exit 1"
else
  not_ok "mutable action ref should trigger exit 1 (got 0)"
fi

# ─── Test 3: missing --locked in ci.yml detected ──────────────────────────────
# cargo build without --locked lets CI resolve a different graph than the one
# cargo-deny audited. The check must flag this.

t="$(setup_fixture t_no_locked_ci)"
write_audit_yml "$t"
write_cargo_toml "$t"
write_clippy_toml "$t"
write_harness_locked "$t"

cat > "$t/.github/workflows/ci.yml" <<'EOF'
name: ci
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # master
        with:
          toolchain: stable
      - run: cargo build --all
      - run: cargo test --all --locked
      - run: cargo clippy --locked
  msrv:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # master
        with:
          toolchain: "1.93"
      - run: cargo build --locked
EOF

exit_code=0
run_sut "$t" > /dev/null || exit_code=$?
if [ "$exit_code" -ne 0 ]; then
  ok "cargo build without --locked in ci.yml triggers exit 1"
else
  not_ok "missing --locked in ci.yml should trigger exit 1 (got 0)"
fi

# ─── Test 4: missing --locked in harness detected ─────────────────────────────
# The integration harness is a separate check from ci.yml; it must carry
# --locked so the live test binary matches the cargo-deny-audited graph.

t="$(setup_fixture t_no_locked_harness)"
write_ci_yml_valid "$t"
write_audit_yml "$t"
write_cargo_toml "$t"
write_clippy_toml "$t"

cat > "$t/scripts/matrix_integration_test.sh" <<'EOF'
#!/usr/bin/env bash
cargo test -p mx-agent-daemon --test matrix_integration -- --ignored --test-threads=1
EOF

exit_code=0
run_sut "$t" > /dev/null || exit_code=$?
if [ "$exit_code" -ne 0 ]; then
  ok "cargo test without --locked in harness triggers exit 1"
else
  not_ok "missing --locked in harness should trigger exit 1 (got 0)"
fi

# ─── Test 5: missing timeout-minutes detected ─────────────────────────────────
# A job without timeout-minutes holds a GitHub runner for 360 minutes on hang.
# The check must catch even a single job that omits it.

t="$(setup_fixture t_no_timeout)"
write_audit_yml "$t"
write_cargo_toml "$t"
write_clippy_toml "$t"
write_harness_locked "$t"

cat > "$t/.github/workflows/ci.yml" <<'EOF'
name: ci
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # master
        with:
          toolchain: stable
      - run: cargo build --locked
      - run: cargo test --locked
  msrv:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # master
        with:
          toolchain: "1.93"
      - run: cargo build --locked
EOF

exit_code=0
run_sut "$t" > /dev/null || exit_code=$?
if [ "$exit_code" -ne 0 ]; then
  ok "job without timeout-minutes triggers exit 1"
else
  not_ok "missing timeout-minutes should trigger exit 1 (got 0)"
fi

# ─── Test 6: missing MSRV job detected ────────────────────────────────────────
# ci.yml with no 'msrv:' job means the declared MSRV is never built; regressions
# go unnoticed until a downstream consumer tries to build on that toolchain.

t="$(setup_fixture t_no_msrv_job)"
write_audit_yml "$t"
write_cargo_toml "$t"
write_clippy_toml "$t"
write_harness_locked "$t"

cat > "$t/.github/workflows/ci.yml" <<'EOF'
name: ci
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # master
        with:
          toolchain: stable
      - run: cargo build --locked
      - run: cargo test --locked
EOF

exit_code=0
run_sut "$t" > /dev/null || exit_code=$?
if [ "$exit_code" -ne 0 ]; then
  ok "ci.yml without 'msrv:' job triggers exit 1"
else
  not_ok "missing msrv job should trigger exit 1 (got 0)"
fi

# ─── Test 7: MSRV version mismatch detected ───────────────────────────────────
# Cargo.toml and clippy.toml say 1.93 but the msrv CI job uses toolchain: "1.74".
# The three machine-read MSRV sites must agree, or the drift goes silently wrong.

t="$(setup_fixture t_msrv_mismatch)"
write_audit_yml "$t"
write_cargo_toml "$t"    # rust-version = "1.93"
write_clippy_toml "$t"   # msrv = "1.93"
write_harness_locked "$t"

cat > "$t/.github/workflows/ci.yml" <<'EOF'
name: ci
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # master
        with:
          toolchain: stable
      - run: cargo build --locked
      - run: cargo test --locked
  msrv:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # master
        with:
          toolchain: "1.74"
      - run: cargo build --locked
EOF

exit_code=0
run_sut "$t" > /dev/null || exit_code=$?
if [ "$exit_code" -ne 0 ]; then
  ok "MSRV mismatch (job=1.74 vs Cargo.toml/clippy.toml=1.93) triggers exit 1"
else
  not_ok "MSRV version mismatch should trigger exit 1 (got 0)"
fi

# ─── Test 8: missing audit.yml detected ───────────────────────────────────────
# Without audit.yml there is no scheduled advisory check; a new RustSec
# advisory only surfaces on the next push, not within a week.

t="$(setup_fixture t_no_audit)"
write_ci_yml_valid "$t"
write_cargo_toml "$t"
write_clippy_toml "$t"
write_harness_locked "$t"
# Deliberately do not write audit.yml.

exit_code=0
run_sut "$t" > /dev/null || exit_code=$?
if [ "$exit_code" -ne 0 ]; then
  ok "absent audit.yml triggers exit 1"
else
  not_ok "absent audit.yml should trigger exit 1 (got 0)"
fi

# ─── Test 9: audit.yml without workflow_dispatch detected ─────────────────────
# schedule-only audit.yml cannot be triggered manually for a one-off check;
# workflow_dispatch is required.

t="$(setup_fixture t_audit_no_dispatch)"
write_ci_yml_valid "$t"
write_cargo_toml "$t"
write_clippy_toml "$t"
write_harness_locked "$t"

cat > "$t/.github/workflows/audit.yml" <<'EOF'
name: audit
on:
  schedule:
    - cron: "17 6 * * 1"
jobs:
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: EmbarkStudios/cargo-deny-action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v2
        with:
          command: check advisories
EOF

exit_code=0
run_sut "$t" > /dev/null || exit_code=$?
if [ "$exit_code" -ne 0 ]; then
  ok "audit.yml without workflow_dispatch triggers exit 1"
else
  not_ok "audit.yml missing workflow_dispatch should trigger exit 1 (got 0)"
fi

# ─── Test 10: dtolnay/rust-toolchain step without toolchain: input detected ───
# Pinning the action to a SHA silently drops the @stable branch's implicit
# default toolchain; every dtolnay/rust-toolchain step must name it explicitly.

t="$(setup_fixture t_no_toolchain_input)"
write_audit_yml "$t"
write_cargo_toml "$t"
write_clippy_toml "$t"
write_harness_locked "$t"

# build job has a dtolnay step with no with:/toolchain: block; msrv job has one.
# dtolnay_steps=2, toolchain_inputs=1 → check fires.
cat > "$t/.github/workflows/ci.yml" <<'EOF'
name: ci
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # master
      - run: cargo build --locked
      - run: cargo test --locked
  msrv:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # master
        with:
          toolchain: "1.93"
      - run: cargo build --locked
EOF

exit_code=0
run_sut "$t" > /dev/null || exit_code=$?
if [ "$exit_code" -ne 0 ]; then
  ok "dtolnay/rust-toolchain step without toolchain: input triggers exit 1"
else
  not_ok "missing toolchain: input should trigger exit 1 (got 0)"
fi

# ─── Test 11: real project repository passes (regression guard) ───────────────

exit_code=0
(cd "$repo_root" && bash "$sut") > /dev/null 2>&1 || exit_code=$?
if [ "$exit_code" -eq 0 ]; then
  ok "real project repository passes test_ci_yml.sh (no regression)"
else
  not_ok "real project repository FAILS test_ci_yml.sh — regression!"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "Results: $pass passed, $fail failed"
if [ "$fail" -gt 0 ]; then
  exit 1
fi
