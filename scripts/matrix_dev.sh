#!/usr/bin/env bash
# matrix_dev.sh — manage a local Tuwunel Matrix homeserver for mx-agent dev/e2e.
#
# Brings up a throwaway, localhost-only Matrix homeserver in Docker and provides
# helpers to register/login test users and mint access tokens. Intended for
# local development and the integration/e2e tests (issues #59–#61). See
# dev/matrix/README.md.
#
# Usage:
#   scripts/matrix_dev.sh <command> [args]
#
# Commands:
#   up                      Start the homeserver and wait until it is ready.
#   down                    Stop the homeserver (keeps data).
#   reset                   Stop and delete all homeserver data (fresh state).
#   status                  Show whether the homeserver is up and its URL.
#   logs                    Follow the homeserver logs.
#   url                     Print the client base URL.
#   register <user> [pass]  Register a user via the registration token; prints
#                           the user id and an access token.
#   login <user> [pass]     Log in an existing user; prints an access token.
#
# Environment (from dev/matrix/.env, auto-created from .env.example):
#   MATRIX_REGISTRATION_TOKEN  Registration token for the dev homeserver.
#   MATRIX_PORT                Host loopback port (default 8008).
#
# Requirements: docker (with compose v2), curl, jq.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MATRIX_DIR="$SCRIPT_DIR/../dev/matrix"
COMPOSE_FILE="$MATRIX_DIR/docker-compose.yml"
ENV_FILE="$MATRIX_DIR/.env"

die() { echo "error: $*" >&2; exit 1; }
note() { echo ">> $*" >&2; }
usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

command -v docker >/dev/null 2>&1 || die "docker not found"
command -v curl >/dev/null 2>&1 || die "curl not found"
command -v jq >/dev/null 2>&1 || die "jq not found"
[ -f "$COMPOSE_FILE" ] || die "compose file not found: $COMPOSE_FILE"

# Create dev/matrix/.env from the example on first use, with a random token.
ensure_env_file() {
  [ -f "$ENV_FILE" ] && return 0
  note "creating $ENV_FILE (first run)"
  local token
  token="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | cut -c1-32)"
  {
    echo "MATRIX_REGISTRATION_TOKEN=$token"
    echo "MATRIX_PORT=8008"
  } >"$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

# Load MATRIX_* from the env file.
load_env() {
  ensure_env_file
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
  MATRIX_PORT="${MATRIX_PORT:-8008}"
  BASE_URL="http://127.0.0.1:${MATRIX_PORT}"
}

compose() { docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }

wait_ready() {
  note "waiting for homeserver at $BASE_URL ..."
  local i
  for i in $(seq 1 60); do
    if curl -fsS "$BASE_URL/_matrix/client/versions" >/dev/null 2>&1; then
      note "homeserver ready after ${i}s"
      return 0
    fi
    sleep 1
  done
  die "homeserver did not become ready in time (try: scripts/matrix_dev.sh logs)"
}

cmd_up() {
  load_env
  compose up -d
  wait_ready
  echo "$BASE_URL"
}

cmd_down() {
  load_env
  compose down
}

cmd_reset() {
  load_env
  compose down -v
  note "homeserver data removed"
}

cmd_status() {
  load_env
  if curl -fsS "$BASE_URL/_matrix/client/versions" >/dev/null 2>&1; then
    echo "homeserver: up ($BASE_URL)"
  else
    echo "homeserver: down"
    return 3
  fi
}

cmd_logs() {
  load_env
  compose logs -f
}

cmd_url() {
  load_env
  echo "$BASE_URL"
}

# Register a user through the single-stage registration-token flow and print
# the resulting user id and access token as JSON.
cmd_register() {
  load_env
  local user="${1:?usage: register <user> [pass]}"
  local pass="${2:-${user}-pass}"
  [ -n "${MATRIX_REGISTRATION_TOKEN:-}" ] || die "MATRIX_REGISTRATION_TOKEN not set in $ENV_FILE"

  local session
  session="$(curl -sS -X POST "$BASE_URL/_matrix/client/v3/register?kind=user" \
    -H 'Content-Type: application/json' -d '{}' | jq -r '.session // empty')"
  [ -n "$session" ] || die "could not start registration (is the homeserver up?)"

  local body resp
  body="$(jq -n --arg u "$user" --arg p "$pass" --arg t "$MATRIX_REGISTRATION_TOKEN" --arg s "$session" \
    '{username:$u, password:$p, device_id:"MXAGENTDEV", initial_device_display_name:"mx-agent-dev",
      auth:{type:"m.login.registration_token", token:$t, session:$s}}')"
  resp="$(curl -sS -X POST "$BASE_URL/_matrix/client/v3/register?kind=user" \
    -H 'Content-Type: application/json' -d "$body")"

  if [ "$(jq -r 'has("access_token")' <<<"$resp")" != "true" ]; then
    die "registration failed: $(jq -rc '.error // .' <<<"$resp")"
  fi
  jq '{user_id, device_id, access_token, home_server: "'"$BASE_URL"'"}' <<<"$resp"
}

# Log in an existing user and print the user id and a fresh access token.
cmd_login() {
  load_env
  local user="${1:?usage: login <user> [pass]}"
  local pass="${2:-${user}-pass}"

  local body resp
  body="$(jq -n --arg u "$user" --arg p "$pass" \
    '{type:"m.login.password", identifier:{type:"m.id.user", user:$u}, password:$p,
      initial_device_display_name:"mx-agent-dev"}')"
  resp="$(curl -sS -X POST "$BASE_URL/_matrix/client/v3/login" \
    -H 'Content-Type: application/json' -d "$body")"

  if [ "$(jq -r 'has("access_token")' <<<"$resp")" != "true" ]; then
    die "login failed: $(jq -rc '.error // .' <<<"$resp")"
  fi
  jq '{user_id, device_id, access_token, home_server: "'"$BASE_URL"'"}' <<<"$resp"
}

[ $# -gt 0 ] || { usage; exit 2; }
cmd="$1"; shift
case "$cmd" in
  up) cmd_up "$@" ;;
  down) cmd_down "$@" ;;
  reset) cmd_reset "$@" ;;
  status) cmd_status "$@" ;;
  logs) cmd_logs "$@" ;;
  url) cmd_url "$@" ;;
  register) cmd_register "$@" ;;
  login) cmd_login "$@" ;;
  -h|--help|help) usage ;;
  *) die "unknown command: $cmd (see --help)" ;;
esac
