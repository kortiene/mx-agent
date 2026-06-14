#!/usr/bin/env bash
# check-doc-claims.sh — guard the docs against E2EE confidentiality over-claims.
#
# Under `workspace create --e2ee on` (issue #249, shipped) workspace **timeline**
# traffic — exec/call requests, results, stream chunks, the artifact/share
# referencing events, heartbeats — and the **media offload** (>256 KiB exec
# output and large shares, issue #308) are Megolm/`EncryptedFile`-encrypted and
# not readable by the homeserver operator. Matrix **state** events are a separate
# channel that Megolm NEVER covers: the `com.mxagent.task.v1` action
# (`command`/`cwd`/`env`) and result, and the `invocation`/`agent`/`workspace`
# state, stay plaintext readable by the operator even in an encrypted room. So
# docs must not claim *whole-workspace* confidentiality, and must not use the
# unscoped phrase "opaque to the homeserver" — confidentiality has to be scoped
# to timeline + media, with the plaintext-state caveat stated.
#
# The check uses a DENYLIST of substrings that only ever appear in over-claims,
# rather than a broad `E2EE` match — legitimate mentions ("E2EE encryption
# disabled", device-transport identity) must NOT trip it. This regression
# already happened once (#270 re-introduced the claim that #252 removed); this
# lint stops it recurring.
#
# Usage: scripts/check-doc-claims.sh
# Exit:  0 = clean, 1 = over-claim(s) found (offending file:line printed).

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

# Files scanned for confidentiality over-claims: README plus all of docs/.
files=("README.md")
while IFS= read -r doc; do
  files+=("$doc")
done < <(find docs -maxdepth 1 -name '*.md' -type f | sort)

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
  "opaque to the homeserver"
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
  echo "Under --e2ee on, workspace TIMELINE traffic and MEDIA offload are" >&2
  echo "encrypted, but Matrix STATE events (task action command/env/result," >&2
  echo "invocation/agent/workspace state) stay plaintext readable by the" >&2
  echo "homeserver operator. Do not claim whole-workspace confidentiality or" >&2
  echo "use the unscoped phrase 'opaque to the homeserver'; scope it to" >&2
  echo "timeline + media and keep the plaintext-state caveat. See #308 and" >&2
  echo "scripts/check-doc-claims.sh." >&2
  exit 1
fi

echo "check-doc-claims: no E2EE confidentiality over-claims found."
