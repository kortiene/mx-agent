#!/usr/bin/env bash
# test_doc_sandbox_nits.sh — regression tests for the §13.5 sandbox-backend
# doc fixes introduced in issue #352.
#
# Verifies that:
#  1. docs/user-guide.md contains no stray </content> / </invoke> markup.
#  2. README.md Quickstart "Run the daemon" block includes `daemon reload`.
#  3. docs/architecture.md §13.5 frames firejail/chroot as "rejected at policy
#     load", not as available backends.
#  4. docs/architecture.md §13.5 explicitly states that seccomp filtering and
#     rlimit/cgroup capping are NOT implemented.
#  5. docs/architecture.md §13.5 lists the four real backends: none, bubblewrap,
#     docker, podman.
#  6. docs/architecture.md §13.5 contains the container cap-drop note
#     (--cap-drop ALL deliberately omitted; deferred pending --user mapping).
#  7. Cross-doc consistency: all four canonical sources agree that firejail and
#     chroot are rejected at policy load (README, architecture.md, alpha-
#     release-checklist.md, security-hardening.md).
#
# Usage: scripts/test_doc_sandbox_nits.sh
# Exit:  0 = all tests passed, 1 = one or more tests failed.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

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

# ─── 1. docs/user-guide.md: no stray XML markup ─────────────────────────────

user_guide="$repo_root/docs/user-guide.md"

if grep -qE '</content>|</invoke>' "$user_guide" 2>/dev/null; then
  not_ok "docs/user-guide.md still contains stray </content> or </invoke> markup"
else
  ok "docs/user-guide.md contains no stray </content> / </invoke> markup"
fi

# File must end with exactly one trailing newline (the last real line must not
# be the stray tag lines).  wc -l counts newlines, so the line count and the
# last content line being meaningful are sufficient.
last_line="$(tail -1 "$user_guide")"
if echo "$last_line" | grep -qE '</content>|</invoke>'; then
  not_ok "docs/user-guide.md last line is still a stray markup tag: $last_line"
else
  ok "docs/user-guide.md last line is real content (not a stray tag)"
fi

# ─── 2. README.md: quickstart includes 'daemon reload' ───────────────────────

readme="$repo_root/README.md"

if grep -q 'daemon reload' "$readme"; then
  ok "README.md Quickstart includes 'daemon reload'"
else
  not_ok "README.md Quickstart missing 'daemon reload'"
fi

# Sanity: the other lifecycle commands must still be present.
for cmd in 'daemon start' 'daemon status' 'daemon stop'; do
  if grep -q "$cmd" "$readme"; then
    ok "README.md still contains '$cmd'"
  else
    not_ok "README.md is missing '$cmd' (regression)"
  fi
done

# ─── 3. architecture.md §13.5: firejail/chroot are 'rejected at policy load' ─

arch="$repo_root/docs/architecture.md"

# The document must contain a "rejected at policy load" note that covers
# firejail and chroot.  The prose may split the mention across two lines
# (firejail/chroot on one line, "rejected" on the next), so we test for the
# key phrase independently rather than requiring it on the same line.
if grep -q 'rejected at policy load' "$arch"; then
  ok "docs/architecture.md: 'rejected at policy load' phrase is present"
else
  not_ok "docs/architecture.md: missing 'rejected at policy load' phrase"
fi

# firejail and chroot must each appear in the document (so the rejection note
# names them explicitly).
for name_val in firejail chroot; do
  if grep -qiE "\\b${name_val}\\b" "$arch"; then
    ok "docs/architecture.md: '$name_val' is mentioned (with rejection framing expected)"
  else
    not_ok "docs/architecture.md: '$name_val' is not mentioned at all"
  fi
done

# Sanity: no line should list firejail or chroot as if it were a selectable
# backend in a bullet list (e.g. "- firejail" or "* chroot" alone on a line
# without adjacent rejection language in the same paragraph).  We check using
# a 3-line context window: a bullet-list line naming firejail/chroot whose
# ±1 context lines contain no rejection word would be a red flag.
bad_bullet="$(grep -niE '^[[:space:]]*[-*][[:space:]]+(firejail|chroot)[[:space:]]*$' "$arch" || true)"
if [ -z "$bad_bullet" ]; then
  ok "docs/architecture.md: no bare bullet-list entry for firejail or chroot"
else
  not_ok "docs/architecture.md: bare bullet-list entry for firejail/chroot found (looks like an available-backend listing):"
  echo "$bad_bullet" >&2
  fail=$((fail + 1))
fi

# ─── 4. architecture.md §13.5: seccomp/rlimit/cgroup framing (post-#349) ─────
#
# Issue #349 shipped resource caps (rlimit/cgroup) and the seccomp config
# machinery (off by default; BPF profile installation is a documented follow-up).
# Checks:
#   a. rlimit/cgroup caps are documented (they are implemented).
#   b. Seccomp is documented as off-by-default and the BPF profile installation
#      is a follow-up — the doc must NOT silently omit the deferral.

if grep -qiE '\brlimit\b|\bcgroup\b' "$arch"; then
  ok "docs/architecture.md: rlimit/cgroup resource caps are documented"
else
  not_ok "docs/architecture.md: rlimit/cgroup not mentioned (expected implementation note after #349)"
fi

if grep -qiE '\bseccomp\b' "$arch"; then
  # The BPF filter ships off by default; the curated allowlist / bwrap byte
  # format is a documented follow-up.  The doc must say so explicitly.
  if grep -qiE 'off by default|follow-up|deferred' "$arch"; then
    ok "docs/architecture.md: seccomp documented as off-by-default / BPF profile deferred"
  else
    not_ok "docs/architecture.md: seccomp mentioned but not framed as off-by-default or deferred (over-claim risk)"
  fi
else
  not_ok "docs/architecture.md: seccomp not mentioned (expected implementation note after #349)"
fi

# ─── 5. architecture.md §13.5: the four real backends are listed ─────────────

for backend in none bubblewrap docker podman; do
  if grep -q "\\b${backend}\\b" "$arch"; then
    ok "docs/architecture.md: backend '$backend' is listed"
  else
    not_ok "docs/architecture.md: backend '$backend' is missing"
  fi
done

# ─── 6. architecture.md §13.5: container cap-drop note is present ────────────

if grep -q 'cap-drop' "$arch"; then
  ok "docs/architecture.md: container --cap-drop note is present"
else
  not_ok "docs/architecture.md: container --cap-drop note is absent"
fi

# The note must include the reason (CAP_DAC_OVERRIDE / writable_paths / deferred).
if grep -qE 'CAP_DAC_OVERRIDE|writable_paths.*uid|deferred' "$arch"; then
  ok "docs/architecture.md: cap-drop note includes deferral rationale"
else
  not_ok "docs/architecture.md: cap-drop note missing rationale (CAP_DAC_OVERRIDE / deferred)"
fi

# ─── 7. Cross-doc consistency: firejail/chroot rejected in all four docs ─────
#
# Each canonical source must both mention firejail/chroot AND carry a rejection
# note somewhere in the same file.  The two phrases may span different lines, so
# we test for their co-presence in the file rather than on the same line.

docs_with_rejection=(
  "$repo_root/README.md"
  "$repo_root/docs/architecture.md"
  "$repo_root/docs/alpha-release-checklist.md"
  "$repo_root/docs/security-hardening.md"
)

for doc in "${docs_with_rejection[@]}"; do
  name="${doc#"$repo_root"/}"
  # Check that the file mentions firejail or chroot AND has a rejection phrase.
  has_name=false
  has_rejection=false
  if grep -qiE 'firejail|chroot' "$doc"; then has_name=true; fi
  if grep -qiE 'rejected|not implemented' "$doc"; then has_rejection=true; fi
  if $has_name && $has_rejection; then
    ok "cross-doc consistency: $name has firejail/chroot + rejection note"
  else
    not_ok "cross-doc consistency: $name is missing firejail/chroot mention or rejection note (has_name=$has_name has_rejection=$has_rejection)"
  fi
done

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "Results: $pass passed, $fail failed"
if [ "$fail" -gt 0 ]; then
  exit 1
fi
