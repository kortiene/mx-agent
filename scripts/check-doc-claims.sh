#!/usr/bin/env bash
# check-doc-claims.sh — guard the docs against E2EE confidentiality over-claims.
#
# Remote exec/call/share and workspace traffic are Ed25519-SIGNED (integrity +
# authenticity) and authorized by the receiver's deny-by-default policy, but in
# this alpha they transit an UNENCRYPTED Matrix room — readable by the homeserver
# operator. Docs must not claim end-to-end encryption / confidentiality for that
# traffic. This regression already happened once (#270 re-introduced the claim
# that #252 removed); this lint stops it recurring until workspace E2EE lands.
#
# The check uses a DENYLIST of substrings that only ever appear in over-claims,
# rather than a broad `E2EE` match — legitimate mentions ("E2EE encryption
# disabled", device-transport identity, #249 references) must NOT trip it.
#
# RELAX WHEN #249 (workspace room-level E2EE on create) LANDS: once exec/call/
# share traffic is genuinely end-to-end encrypted, remove the now-accurate
# phrases from the denylist below.
#
# Usage: scripts/check-doc-claims.sh
# Exit:  0 = clean, 1 = over-claim(s) found (offending file:line printed).

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

# Files scanned for confidentiality over-claims.
files=(
  "docs/cli-reference.md"
  "README.md"
  "docs/user-guide.md"
)

# Forbidden substrings: phrasings that assert confidentiality for exec/call/
# share/workspace traffic. Case-insensitive. These appear ONLY in over-claims.
patterns=(
  "encrypted at rest and in flight"
  "Only the specified agent can decrypt"
  "All shares are E2EE"
  "signed \+ E2EE"
  "signed, E2EE"
  "end-to-end-encrypted remote"
  "encrypted room state \(E2EE\)"
  "encrypts and uploads"
)

found=0
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  for p in "${patterns[@]}"; do
    if matches="$(grep -niE -- "$p" "$f")"; then
      while IFS= read -r line; do
        echo "$f:$line"
        found=1
      done <<<"$matches"
    fi
  done
done

if [ "$found" -ne 0 ]; then
  echo ""
  echo "ERROR: E2EE/confidentiality over-claim(s) found in docs." >&2
  echo "Remote exec/call/share traffic is Ed25519-signed but NOT end-to-end" >&2
  echo "encrypted in this alpha (workspace rooms are unencrypted; see #249)." >&2
  echo "Reword to state the true trust boundary, or relax this lint once" >&2
  echo "workspace E2EE lands. See scripts/check-doc-claims.sh." >&2
  exit 1
fi

echo "check-doc-claims: no E2EE confidentiality over-claims found."
