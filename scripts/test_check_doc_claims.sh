#!/usr/bin/env bash
# test_check_doc_claims.sh — regression tests for scripts/check-doc-claims.sh
#
# Verifies that the doc-claims lint:
#  1. Exits 0 for a clean file.
#  2. Exits 1 and prints file:line for each forbidden confidentiality over-claim.
#  3. Does NOT flag legitimate E2EE mentions (advisory signal, "disabled", #249).
#  4. Scans README.md and docs/user-guide.md in addition to cli-reference.md.
#  5. The real project docs pass (regression guard).
#
# Usage: scripts/test_check_doc_claims.sh
# Exit:  0 = all tests passed, 1 = one or more tests failed.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
sut="$script_dir/check-doc-claims.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# ─── helpers ─────────────────────────────────────────────────────────────────

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

# Build a minimal fixture directory that mirrors the repo layout the SUT
# expects. We copy the SUT into the fixture's scripts/ dir so that its
# `dirname "$0"/../` resolves to the fixture root, not the real repo root.
setup_fixture_root() {
  local name="$1"
  local froot="$tmpdir/$name"
  mkdir -p "$froot/docs" "$froot/scripts"
  cp "$sut" "$froot/scripts/check-doc-claims.sh"
  echo "$froot"
}

# Write a cli-reference.md that contains only legitimate E2EE mentions.
write_clean_cli_ref() {
  local froot="$1"
  cat > "$froot/docs/cli-reference.md" <<'EOF'
# CLI Reference
The room is created with E2EE encryption disabled (workspace state events must be readable).
Device verification status is an advisory E2EE transport signal.
Room-level E2EE is tracked by #249.
Remote exec is not end-to-end encrypted in this alpha; see workspace create above.
EOF
}

# Run the SUT from within the fixture root.
run_sut() {
  local froot="$1"
  (
    cd "$froot"
    bash scripts/check-doc-claims.sh 2>&1
  )
}

# ─── Test: clean file exits 0 ────────────────────────────────────────────────

t1="$(setup_fixture_root t1_clean)"
write_clean_cli_ref "$t1"
exit_code=0
run_sut "$t1" > /dev/null || exit_code=$?
if [ "$exit_code" -eq 0 ]; then
  ok "clean docs/cli-reference.md exits 0"
else
  not_ok "clean docs/cli-reference.md should exit 0 (got $exit_code)"
fi

# ─── Test: absent files are silently skipped ─────────────────────────────────

t_absent="$(setup_fixture_root t_absent)"
# No docs/ files at all — the SUT skips absent files.
exit_code=0
run_sut "$t_absent" > /dev/null || exit_code=$?
if [ "$exit_code" -eq 0 ]; then
  ok "absent scanned files are silently skipped (exit 0)"
else
  not_ok "absent scanned files should be silently skipped (got $exit_code)"
fi

# ─── Test: each forbidden phrase triggers exit 1 and prints file:line ─────────

forbidden_phrases=(
  "encrypted at rest and in flight"
  "Only the specified agent can decrypt"
  "All shares are E2EE"
  "signed + E2EE"
  "signed, E2EE"
  "end-to-end-encrypted remote"
  "encrypted room state (E2EE)"
  "encrypts and uploads"
)

forbidden_labels=(
  "encrypted-at-rest-and-in-flight"
  "only-specified-agent-can-decrypt"
  "all-shares-are-e2ee"
  "signed-plus-e2ee"
  "signed-comma-e2ee"
  "end-to-end-encrypted-remote"
  "encrypted-room-state-e2ee"
  "encrypts-and-uploads"
)

n="${#forbidden_phrases[@]}"
for (( i=0; i<n; i++ )); do
  phrase="${forbidden_phrases[$i]}"
  label="${forbidden_labels[$i]}"
  tf="$(setup_fixture_root "tf_$label")"
  write_clean_cli_ref "$tf"
  printf '\n%s\n' "$phrase" >> "$tf/docs/cli-reference.md"

  exit_code=0
  output="$(run_sut "$tf" 2>&1 || true)"
  run_sut "$tf" > /dev/null 2>&1 || exit_code=$?

  if [ "$exit_code" -ne 0 ]; then
    ok "forbidden phrase triggers exit 1: $label"
  else
    not_ok "forbidden phrase not detected (exit 0): $label"
  fi

  # SUT must print the offending file:line to stdout.
  if echo "$output" | grep -qF "docs/cli-reference.md:"; then
    ok "offending file:line printed for: $label"
  else
    not_ok "offending file:line missing in output for: $label"
  fi
done

# ─── Test: legitimate E2EE phrases are NOT flagged ───────────────────────────

legitimate_phrases=(
  "The room is created with E2EE encryption disabled"
  "Device verification status is an advisory E2EE transport signal"
  "Room-level E2EE is tracked by #249"
  "handles E2EE crypto state"
  "the device's public Matrix E2EE key"
  "It is not end-to-end encrypted in this alpha"
  "path/network confinement is enforced end-to-end for batch exec"
  "see #249 for workspace E2EE"
)

legitimate_labels=(
  "e2ee-encryption-disabled"
  "advisory-e2ee-transport-signal"
  "tracked-by-249"
  "handles-e2ee-crypto"
  "public-matrix-e2ee-key"
  "not-end-to-end-encrypted-alpha"
  "end-to-end-for-batch-exec"
  "see-249-workspace-e2ee"
)

n="${#legitimate_phrases[@]}"
for (( i=0; i<n; i++ )); do
  phrase="${legitimate_phrases[$i]}"
  label="${legitimate_labels[$i]}"
  tl="$(setup_fixture_root "tl_$label")"
  write_clean_cli_ref "$tl"
  printf '\n%s\n' "$phrase" >> "$tl/docs/cli-reference.md"

  exit_code=0
  run_sut "$tl" > /dev/null 2>&1 || exit_code=$?
  if [ "$exit_code" -eq 0 ]; then
    ok "legitimate phrase is not a false positive: $label"
  else
    not_ok "legitimate phrase triggered a false positive: $label"
  fi
done

# ─── Test: README.md is also scanned ─────────────────────────────────────────

treadme="$(setup_fixture_root t_readme)"
write_clean_cli_ref "$treadme"
printf '\nAll shares are E2EE\n' > "$treadme/README.md"

exit_code=0
run_sut "$treadme" > /dev/null 2>&1 || exit_code=$?
if [ "$exit_code" -ne 0 ]; then
  ok "README.md is scanned for over-claims"
else
  not_ok "README.md over-claim not detected (exit 0)"
fi

# ─── Test: docs/user-guide.md is also scanned ────────────────────────────────

tuserguide="$(setup_fixture_root t_userguide)"
write_clean_cli_ref "$tuserguide"
printf '\nend-to-end-encrypted remote operations\n' > "$tuserguide/docs/user-guide.md"

exit_code=0
run_sut "$tuserguide" > /dev/null 2>&1 || exit_code=$?
if [ "$exit_code" -ne 0 ]; then
  ok "docs/user-guide.md is scanned for over-claims"
else
  not_ok "docs/user-guide.md over-claim not detected (exit 0)"
fi

# ─── Test: real project docs pass (regression guard) ─────────────────────────

exit_code=0
(cd "$repo_root" && bash "$sut") > /dev/null 2>&1 || exit_code=$?
if [ "$exit_code" -eq 0 ]; then
  ok "real project docs pass check-doc-claims.sh (no regression)"
else
  not_ok "real project docs FAIL check-doc-claims.sh — doc regression!"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "Results: $pass passed, $fail failed"
if [ "$fail" -gt 0 ]; then
  exit 1
fi
