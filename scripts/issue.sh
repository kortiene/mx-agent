#!/usr/bin/env bash
# issue.sh — run the `/issue` workflow headlessly via the pi CLI.
#
# This is the non-interactive equivalent of typing `/issue <number> [notes]`
# in pi's editor. It expands the same prompt template (.pi/prompts/issue.md),
# substituting the issue number and notes exactly as pi would, then feeds the
# result to `pi -p` (print mode) so the agent implements the issue end-to-end:
# branch, code, test, PR, watch CI, merge.
#
# Because pi's print-mode exit code only reflects whether the model responded
# (not whether the issue actually shipped), this script verifies against GitHub
# afterward: a run "succeeds" only if the issue ends up CLOSED. Already-closed
# issues are skipped, and unknown issue numbers fail fast before spending tokens.
#
# Usage:
#   scripts/issue.sh <issue-number> [notes...] [-- <extra pi flags>]
#
# Options:
#   --template <path>  Prompt template to expand (default: .pi/prompts/issue.md).
#   --json             Stream pi events as JSON lines (pi --mode json).
#   --model <pattern>  Pass through to pi (e.g. sonnet:high, openai/gpt-4o).
#   --thinking <level> Pass through to pi (off|minimal|low|medium|high|xhigh).
#   --name <name>      Session display name (default: "issue #<number>").
#   --repo <owner/repo> Repository for issue lookups (default: gh-detected).
#   --log-dir <dir>    Tee pi output to <dir>/issue-<n>-<timestamp>.log.
#   --no-verify        Do not check that the issue is CLOSED after the run.
#   --force            Run even if the issue is already CLOSED.
#   --print-prompt     Expand the template and print it; do not run pi.
#   --dry-run          Print the exact pi command; do not run it.
#   --                 Everything after is passed verbatim to pi.
#   -h, --help         Show this help.
#
# Environment:
#   PI_BIN, GH_BIN     Override the pi / gh executables.
#   REPO               Default repository (owner/repo).
#   PI_MODEL, PI_THINKING, MX_AGENT_LOG_DIR  Defaults for the matching flags.
#
# Notes:
#   - In headless mode pi cannot ask interactive questions. The template's
#     "ask whether to continue" step becomes "state the assumption and
#     proceed"; pass a note like "do not continue on unmet deps" to steer it.
#   - Requires `pi` on PATH (or set PI_BIN). gh/git/cargo must be usable by the
#     agent exactly as in interactive runs.

set -euo pipefail

TEMPLATE=".pi/prompts/issue.md"
MODE_ARGS=()
PASSTHRU=()
SESSION_NAME=""
REPO="${REPO:-}"
LOG_DIR="${MX_AGENT_LOG_DIR:-}"
VERIFY=1
FORCE=0
PRINT_PROMPT=0
DRY_RUN=0
ARGS=()

die() { echo "error: $*" >&2; exit 1; }
note() { echo ">> $*" >&2; }
# Print the leading comment block (after the shebang) as help text.
usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

# Seed model/thinking from the environment (overridable by explicit flags).
[ -n "${PI_MODEL:-}" ] && PASSTHRU+=(--model "$PI_MODEL")
[ -n "${PI_THINKING:-}" ] && PASSTHRU+=(--thinking "$PI_THINKING")

# Split CLI args at `--`: before it are our flags/positional args, after it are
# verbatim pi flags.
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --template) shift; TEMPLATE="${1:?--template needs a value}" ;;
    --json) MODE_ARGS=(--mode json) ;;
    --model) shift; PASSTHRU+=(--model "${1:?--model needs a value}") ;;
    --thinking) shift; PASSTHRU+=(--thinking "${1:?--thinking needs a value}") ;;
    --name) shift; SESSION_NAME="${1:?--name needs a value}" ;;
    --repo) shift; REPO="${1:?--repo needs a value}" ;;
    --log-dir) shift; LOG_DIR="${1:?--log-dir needs a value}" ;;
    --no-verify) VERIFY=0 ;;
    --force) FORCE=1 ;;
    --print-prompt) PRINT_PROMPT=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --) shift; PASSTHRU+=("$@"); break ;;
    -*) die "unknown option: $1" ;;
    *) ARGS+=("$1") ;;
  esac
  shift
done

[ "${#ARGS[@]}" -gt 0 ] || { usage; exit 2; }
ISSUE="${ARGS[0]}"
[[ "$ISSUE" =~ ^[0-9]+$ ]] || die "issue must be a number, got: $ISSUE"
[ -f "$TEMPLATE" ] || die "prompt template not found: $TEMPLATE"

# Resolve the pi binary.
PI_BIN="${PI_BIN:-}"
if [ -z "$PI_BIN" ]; then
  if command -v pi >/dev/null 2>&1; then
    PI_BIN="$(command -v pi)"
  elif [ -x "$HOME/.local/share/pi-node/current/bin/pi" ]; then
    PI_BIN="$HOME/.local/share/pi-node/current/bin/pi"
  else
    die "pi CLI not found; install pi or set PI_BIN"
  fi
fi

# Resolve the gh binary (used for skip/verify). Optional unless verification is on.
GH_BIN="${GH_BIN:-}"
if [ -z "$GH_BIN" ]; then
  if command -v gh >/dev/null 2>&1; then
    GH_BIN="$(command -v gh)"
  elif [ -x "$HOME/.local/bin/gh" ]; then
    GH_BIN="$HOME/.local/bin/gh"
  fi
fi

# Report an issue's state via gh, or "UNKNOWN" if it cannot be determined.
issue_state() {
  [ -n "$GH_BIN" ] || { echo "UNKNOWN"; return; }
  local repo_args=()
  [ -n "$REPO" ] && repo_args=(--repo "$REPO")
  "$GH_BIN" issue view "$ISSUE" "${repo_args[@]}" --json state -q .state 2>/dev/null || echo "UNKNOWN"
}

# Strip an optional leading YAML frontmatter block (--- ... ---).
strip_frontmatter() {
  awk '
    NR==1 && $0=="---" { infm=1; next }
    infm && $0=="---"  { infm=0; next }
    !infm              { print }
  ' "$1"
}

# Expand prompt-template arguments the way pi does: $1..$9, $@/$ARGUMENTS,
# ${@:N} and ${@:N:L}. ARGS[0] is $1 (issue number), the rest are notes.
render_template() {
  local out; out="$(strip_frontmatter "$TEMPLATE")"
  local -a a=("${ARGS[@]}")

  # ${@:N} and ${@:N:L} (1-indexed, like pi).
  while [[ "$out" =~ \$\{@:([0-9]+)(:([0-9]+))?\} ]]; do
    local whole="${BASH_REMATCH[0]}" start="${BASH_REMATCH[1]}" len="${BASH_REMATCH[3]}"
    local off=$(( start - 1 )) slice
    if [ -n "$len" ]; then slice="${a[*]:off:len}"; else slice="${a[*]:off}"; fi
    out="${out//"$whole"/$slice}"
  done

  # $@ and $ARGUMENTS = all args joined by space.
  local all="${a[*]}"
  out="${out//\$ARGUMENTS/$all}"
  out="${out//\$@/$all}"

  # $1..$9 positional.
  local i
  for i in 9 8 7 6 5 4 3 2 1; do
    out="${out//\$$i/${a[i-1]:-}}"
  done

  printf '%s' "$out"
}

PROMPT="$(render_template)"

if [ "$PRINT_PROMPT" -eq 1 ]; then
  printf '%s\n' "$PROMPT"
  exit 0
fi

[ -n "$SESSION_NAME" ] || SESSION_NAME="issue #$ISSUE"

CMD=("$PI_BIN" -p "${MODE_ARGS[@]}" --name "$SESSION_NAME" "${PASSTHRU[@]}" "$PROMPT")

if [ "$DRY_RUN" -eq 1 ]; then
  printf '[dry-run]'; printf ' %q' "${CMD[@]}"; echo
  exit 0
fi

# Resolve the repository once (needed for skip/verify) if gh is available.
if [ -z "$REPO" ] && [ -n "$GH_BIN" ]; then
  REPO="$("$GH_BIN" repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)"
fi

# Preflight: skip already-closed issues and fail fast on unknown numbers.
if [ "$VERIFY" -eq 1 ] || [ "$FORCE" -eq 0 ]; then
  if [ -z "$GH_BIN" ]; then
    [ "$VERIFY" -eq 1 ] && die "gh not found but verification is on; install gh, set GH_BIN, or pass --no-verify"
  else
    state="$(issue_state)"
    case "$state" in
      CLOSED)
        if [ "$FORCE" -eq 0 ]; then
          note "issue #$ISSUE is already CLOSED; skipping (use --force to run anyway)"
          exit 0
        fi
        ;;
      UNKNOWN)
        die "issue #$ISSUE not found in ${REPO:-the current repo} (is gh authenticated?)"
        ;;
    esac
  fi
fi

# Run pi, optionally teeing the transcript to a per-issue log file.
LOG_FILE=""
if [ -n "$LOG_DIR" ]; then
  mkdir -p "$LOG_DIR"
  LOG_FILE="$LOG_DIR/issue-$ISSUE-$(date +%Y%m%dT%H%M%S).log"
  note "logging transcript to $LOG_FILE"
fi

note "running /issue $ISSUE headlessly via $PI_BIN (session: $SESSION_NAME)"
set +e
if [ -n "$LOG_FILE" ]; then
  "${CMD[@]}" 2>&1 | tee "$LOG_FILE"
  pi_rc=${PIPESTATUS[0]}
else
  "${CMD[@]}"
  pi_rc=$?
fi
set -e

# Verify the outcome against GitHub: a real success means the issue is CLOSED.
if [ "$VERIFY" -eq 1 ]; then
  state="$(issue_state)"
  if [ "$state" = "CLOSED" ]; then
    note "verified: issue #$ISSUE is CLOSED"
    exit 0
  fi
  die "issue #$ISSUE is still ${state} after the run (pi exit ${pi_rc}); treating as failure"
fi

exit "$pi_rc"
