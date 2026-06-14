#!/usr/bin/env bash
# matrix_integration_test.sh — run the local Matrix integration test (issue #60).
#
# Stands up the throwaway local homeserver (issue #59), registers the test
# users, and runs the daemon's `#[ignore]`d Matrix integration suite against it.
# The suite logs in, restores sessions, drives the real `/sync` loop, and covers
# the live daemon paths end to end — including (issue #260) E2EE restart
# durability (decrypt-after-restart from the persistent crypto store),
# key-backup restore across a re-provision, and the interactive two-daemon SAS
# verification flow. See crates/mx-agent-daemon/tests/matrix_integration.rs and
# dev/matrix/README.md.
#
# Some tests need a homeserver user with pristine state, so they are provisioned
# fresh per run (a unique name registered cleanly each time): the recovery and
# key-backup tests need a pristine cross-signing identity and a clean backup
# version; the two-daemon SAS test needs single-device peers so the all-devices
# `sender_verified == Some(true)` assertion is not defeated by devices a shared
# user accumulates across `login_password` calls in the same run.
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

# The recovery test asserts a freshly bootstrapped cross-signing identity, which
# only holds when the account has no server-side cross-signing identity yet
# (`bootstrap_cross_signing_if_needed` no-ops once one exists). A Matrix account
# keeps that identity server-side, so reusing USER1 makes the test pass once and
# fail on every re-run. Give it a unique, freshly-registered user per run so it
# always starts from a pristine cross-signing state.
USER_REC="mxagent_it_recovery_$$_${RANDOM}"
PASS_REC="${USER_REC}-pass"

# The key-backup restore test (issue #260) likewise needs a pristine
# cross-signing identity and a clean backup version, so it gets its own
# fresh-per-run user.
USER_BACKUP="mxagent_it_backup_$$_${RANDOM}"
PASS_BACKUP="${USER_BACKUP}-pass"

# The two-daemon SAS test (issue #260) needs both peers to have exactly one
# device, so the all-devices `sender_verified == Some(true)` assertion is not
# defeated by devices the shared users accumulate across `login_password` calls
# in the same run. Give each side a fresh-per-run single-device user.
USER_SAS1="mxagent_it_sas1_$$_${RANDOM}"
PASS_SAS1="${USER_SAS1}-pass"
USER_SAS2="mxagent_it_sas2_$$_${RANDOM}"
PASS_SAS2="${USER_SAS2}-pass"

# The process-level no-secrets-in-logs test (issue #311) enables recovery via the
# real daemon, which needs a pristine cross-signing identity to bootstrap cleanly
# regardless of which recovery test runs first. Give it its own fresh-per-run
# user so it never collides with the recovery/key-backup users above.
USER_LOGREDACT="mxagent_it_logredact_$$_${RANDOM}"
PASS_LOGREDACT="${USER_LOGREDACT}-pass"

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
# Fresh per run, so the unique names always register cleanly (never reused).
ensure_user "$USER_REC" "$PASS_REC"
ensure_user "$USER_BACKUP" "$PASS_BACKUP"
ensure_user "$USER_SAS1" "$PASS_SAS1"
ensure_user "$USER_SAS2" "$PASS_SAS2"
ensure_user "$USER_LOGREDACT" "$PASS_LOGREDACT"

# The no-secrets-in-logs test (issue #311) drives the compiled `mx-agent` binary
# as a child process (it must read the real `daemon.log`). That binary lives in
# the `mx-agent-cli` crate, which the daemon test target does not pull in, so
# build it explicitly before running the suite.
note "building mx-agent CLI binary"
( cd "$REPO_DIR" && cargo build -p mx-agent-cli --bin mx-agent )

note "running integration test against $HOMESERVER"
set +e
(
  cd "$REPO_DIR"
  MX_AGENT_TEST_HOMESERVER="$HOMESERVER" \
  MX_AGENT_TEST_USER="$USER1" \
  MX_AGENT_TEST_PASSWORD="$PASS1" \
  MX_AGENT_TEST_USER2="$USER2" \
  MX_AGENT_TEST_PASSWORD2="$PASS2" \
  MX_AGENT_TEST_RECOVERY_USER="$USER_REC" \
  MX_AGENT_TEST_RECOVERY_PASSWORD="$PASS_REC" \
  MX_AGENT_TEST_BACKUP_USER="$USER_BACKUP" \
  MX_AGENT_TEST_BACKUP_PASSWORD="$PASS_BACKUP" \
  MX_AGENT_TEST_SAS_USER="$USER_SAS1" \
  MX_AGENT_TEST_SAS_PASSWORD="$PASS_SAS1" \
  MX_AGENT_TEST_SAS_USER2="$USER_SAS2" \
  MX_AGENT_TEST_SAS_PASSWORD2="$PASS_SAS2" \
  MX_AGENT_TEST_LOGREDACT_USER="$USER_LOGREDACT" \
  MX_AGENT_TEST_LOGREDACT_PASSWORD="$PASS_LOGREDACT" \
    cargo test -p mx-agent-daemon --test matrix_integration -- --ignored --nocapture --test-threads=1
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
