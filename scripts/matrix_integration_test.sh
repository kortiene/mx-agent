#!/usr/bin/env bash
# matrix_integration_test.sh — run the local Matrix integration test (issue #60).
#
# Stands up the throwaway local homeserver (issue #59), registers two test
# users, and runs the daemon's `#[ignore]`d Matrix integration test against it.
# The test logs in, restores a session, drives the real `/sync` loop, and
# asserts the daemon observes a message sent by the second user. See
# crates/mx-agent-daemon/tests/matrix_integration.rs and dev/matrix/README.md.
#
# Usage:
#   scripts/matrix_integration_test.sh [--teardown]
#
# Options:
#   --teardown   Stop the homeserver after the test (default: leave it running
#                so repeat runs are fast).
#
# Requirements: docker (compose v2), curl, jq, and a Rust toolchain (cargo).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MATRIX_DEV="$SCRIPT_DIR/matrix_dev.sh"

TEARDOWN=0
for arg in "$@"; do
  case "$arg" in
    --teardown) TEARDOWN=1 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "error: unknown option: $arg (see --help)" >&2; exit 2 ;;
  esac
done

note() { echo ">> $*" >&2; }

# Two dedicated test users; passwords follow matrix_dev.sh's `<user>-pass`
# default so register and login agree.
USER1="mxagent_it_alice"
USER2="mxagent_it_bob"
PASS1="${USER1}-pass"
PASS2="${USER2}-pass"

# Register a user if needed; fall back to login so re-runs (where the user
# already exists) still succeed. Both paths confirm the credentials work.
ensure_user() {
  local user="$1" pass="$2"
  if "$MATRIX_DEV" register "$user" "$pass" >/dev/null 2>&1; then
    note "registered $user"
  elif "$MATRIX_DEV" login "$user" "$pass" >/dev/null 2>&1; then
    note "reusing existing $user"
  else
    echo "error: could not register or log in $user" >&2
    exit 1
  fi
}

note "starting local homeserver"
"$MATRIX_DEV" up >/dev/null
HOMESERVER="$("$MATRIX_DEV" url)"

ensure_user "$USER1" "$PASS1"
ensure_user "$USER2" "$PASS2"

note "running integration test against $HOMESERVER"
set +e
(
  cd "$REPO_DIR"
  MX_AGENT_TEST_HOMESERVER="$HOMESERVER" \
  MX_AGENT_TEST_USER="$USER1" \
  MX_AGENT_TEST_PASSWORD="$PASS1" \
  MX_AGENT_TEST_USER2="$USER2" \
  MX_AGENT_TEST_PASSWORD2="$PASS2" \
    cargo test -p mx-agent-daemon --test matrix_integration -- --ignored --nocapture
)
status=$?
set -e

if [ "$TEARDOWN" -eq 1 ]; then
  note "stopping homeserver"
  "$MATRIX_DEV" down >/dev/null
fi

if [ "$status" -eq 0 ]; then
  note "integration test passed"
else
  note "integration test failed (exit $status)"
fi
exit "$status"
