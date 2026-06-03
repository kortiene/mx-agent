#!/usr/bin/env bash
# issue.sh — run the `/issue` workflow headlessly via a coding-agent runner.
#
# This is the non-interactive equivalent of typing `/issue <number> [notes]`
# in the agent's editor. It expands the same prompt template, substituting the
# issue number and notes, then feeds the result to the selected runner in print
# mode so the agent implements the issue end-to-end: branch, code, test, PR,
# watch CI, merge.
#
# Two runners are supported (select with --runner or MX_AGENT_RUNNER):
#   pi      (default)  pi -p [--mode json] --name N [--model M] [--thinking T] PROMPT
#   claude             claude -p [--output-format stream-json --verbose] [--model M] PROMPT
#
# Because a runner's print-mode exit code only reflects whether the model
# responded (not whether the issue actually shipped), this script verifies
# against GitHub afterward: a run "succeeds" only if the issue ends up CLOSED.
# Already-closed issues are skipped, and unknown issue numbers fail fast before
# spending tokens.
#
# Usage:
#   scripts/issue.sh <issue-number> [notes...] [-- <extra runner flags>]
#
# Options:
#   --runner <name>    Agent runner: pi (default) or claude. Env: MX_AGENT_RUNNER.
#   --template <path>  Prompt template to expand. Default: .claude/commands/issue.md
#                      for claude (if present), else .pi/prompts/issue.md.
#   --json             Stream runner events as JSON (pi --mode json /
#                      claude --output-format stream-json --verbose).
#   --model <pattern>  Pass through as the runner's --model (e.g. sonnet, opus,
#                      sonnet:high, openai/gpt-4o).
#   --thinking <level> Pass through to pi (off|minimal|low|medium|high|xhigh).
#                      Ignored by the claude runner (no equivalent flag).
#   --name <name>      Session display name (pi only; default: "issue #<number>").
#   --repo <owner/repo> Repository for issue lookups (default: gh-detected).
#   --log-dir <dir>    Tee runner output to <dir>/issue-<n>-<timestamp>.log.
#   --timeout <secs>   Abort the run after this many seconds (0 = none).
#   --no-verify        Do not check that the issue is CLOSED after the run.
#   --force            Run even if the issue is already CLOSED.
#   --allow-dirty      Skip the clean-working-tree precondition check.
#   --yes, -y          Do not prompt for confirmation before running.
#   --print-prompt     Expand the template and print it; do not run the agent.
#   --dry-run          Print the exact runner command; do not run it.
#   --                 Everything after is passed verbatim to the runner.
#   -h, --help         Show this help.
#
# Environment:
#   MX_AGENT_RUNNER    Default runner (pi|claude).
#   PI_BIN, CLAUDE_BIN, GH_BIN  Override the runner / gh executables.
#   REPO               Default repository (owner/repo).
#   MX_AGENT_YES=1     Assume "yes" to the confirmation prompt.
#   PI_MODEL, PI_THINKING, MX_AGENT_LOG_DIR  Defaults for the matching flags.
#
# Notes:
#   - In headless mode the agent cannot ask interactive questions. The template's
#     "ask whether to continue" step becomes "state the assumption and
#     proceed"; pass a note like "do not continue on unmet deps" to steer it.
#   - The claude runner needs permission to edit files and run git/gh/cargo
#     non-interactively; pass the appropriate flag after `--`, e.g.
#     `-- --permission-mode acceptEdits` or `-- --dangerously-skip-permissions`.
#   - Requires the chosen runner on PATH (or set PI_BIN / CLAUDE_BIN). gh/git/
#     cargo must be usable by the agent exactly as in interactive runs.

set -euo pipefail

RUNNER="${MX_AGENT_RUNNER:-pi}"
TEMPLATE=""
TEMPLATE_SET=0
JSON_MODE=0
MODEL="${PI_MODEL:-}"
THINKING="${PI_THINKING:-}"
PASSTHRU=()
SESSION_NAME=""
REPO="${REPO:-}"
LOG_DIR="${MX_AGENT_LOG_DIR:-}"
TIMEOUT=0
VERIFY=1
FORCE=0
ALLOW_DIRTY=0
ASSUME_YES=0
[ "${MX_AGENT_YES:-0}" = "1" ] && ASSUME_YES=1
PRINT_PROMPT=0
DRY_RUN=0
ARGS=()

die() { echo "error: $*" >&2; exit 1; }
note() { echo ">> $*" >&2; }
# Print the leading comment block (after the shebang) as help text.
usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

# Split CLI args at `--`: before it are our flags/positional args, after it are
# verbatim runner flags.
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --runner) shift; RUNNER="${1:?--runner needs a value}" ;;
    --template) shift; TEMPLATE="${1:?--template needs a value}"; TEMPLATE_SET=1 ;;
    --json) JSON_MODE=1 ;;
    --model) shift; MODEL="${1:?--model needs a value}" ;;
    --thinking) shift; THINKING="${1:?--thinking needs a value}" ;;
    --name) shift; SESSION_NAME="${1:?--name needs a value}" ;;
    --repo) shift; REPO="${1:?--repo needs a value}" ;;
    --log-dir) shift; LOG_DIR="${1:?--log-dir needs a value}" ;;
    --timeout) shift; TIMEOUT="${1:?--timeout needs a value}" ;;
    --no-verify) VERIFY=0 ;;
    --force) FORCE=1 ;;
    --allow-dirty) ALLOW_DIRTY=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    --print-prompt) PRINT_PROMPT=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --) shift; PASSTHRU+=("$@"); break ;;
    -*) die "unknown option: $1" ;;
    *) ARGS+=("$1") ;;
  esac
  shift
done

# Validate the runner and resolve the default prompt template (the script does
# its own argument substitution, so the template body is portable across
# runners).
case "$RUNNER" in
  pi|claude) ;;
  *) die "unknown --runner: $RUNNER (want: pi or claude)" ;;
esac
if [ "$TEMPLATE_SET" -eq 0 ]; then
  if [ "$RUNNER" = claude ] && [ -f ".claude/commands/issue.md" ]; then
    TEMPLATE=".claude/commands/issue.md"
  else
    TEMPLATE=".pi/prompts/issue.md"
  fi
fi

[ "${#ARGS[@]}" -gt 0 ] || { usage; exit 2; }
ISSUE="${ARGS[0]}"
[[ "$ISSUE" =~ ^[0-9]+$ ]] || die "issue must be a number, got: $ISSUE"
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "--timeout must be a number of seconds"
[ -f "$TEMPLATE" ] || die "prompt template not found: $TEMPLATE"

# Resolve the runner binary into RUNNER_BIN, dispatching on the chosen runner.
resolve_runner_bin() {
  case "$RUNNER" in
    pi)
      if [ -n "${PI_BIN:-}" ]; then
        RUNNER_BIN="$PI_BIN"
      elif command -v pi >/dev/null 2>&1; then
        RUNNER_BIN="$(command -v pi)"
      elif [ -x "$HOME/.local/share/pi-node/current/bin/pi" ]; then
        RUNNER_BIN="$HOME/.local/share/pi-node/current/bin/pi"
      else
        die "pi CLI not found; install pi or set PI_BIN"
      fi
      ;;
    claude)
      if [ -n "${CLAUDE_BIN:-}" ]; then
        RUNNER_BIN="$CLAUDE_BIN"
      elif command -v claude >/dev/null 2>&1; then
        RUNNER_BIN="$(command -v claude)"
      elif [ -x "$HOME/.claude/local/claude" ]; then
        RUNNER_BIN="$HOME/.claude/local/claude"
      elif [ -x "$HOME/.local/bin/claude" ]; then
        RUNNER_BIN="$HOME/.local/bin/claude"
      else
        die "claude CLI not found; install Claude Code or set CLAUDE_BIN"
      fi
      ;;
  esac
}
RUNNER_BIN=""
resolve_runner_bin

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

# Map the neutral options onto the selected runner's print-mode invocation.
build_runner_cmd() {
  case "$RUNNER" in
    pi)
      CMD=("$RUNNER_BIN" -p)
      [ "$JSON_MODE" -eq 1 ] && CMD+=(--mode json)
      CMD+=(--name "$SESSION_NAME")
      [ -n "$MODEL" ] && CMD+=(--model "$MODEL")
      [ -n "$THINKING" ] && CMD+=(--thinking "$THINKING")
      CMD+=("${PASSTHRU[@]}" "$PROMPT")
      ;;
    claude)
      [ -n "$THINKING" ] && note "thinking level '$THINKING' is ignored by the claude runner"
      CMD=("$RUNNER_BIN" -p)
      [ "$JSON_MODE" -eq 1 ] && CMD+=(--output-format stream-json --verbose)
      [ -n "$MODEL" ] && CMD+=(--model "$MODEL")
      CMD+=("${PASSTHRU[@]}" "$PROMPT")
      ;;
  esac
}
CMD=()
build_runner_cmd

# Wrap with a timeout if requested and available.
RUN_CMD=("${CMD[@]}")
if [ "$TIMEOUT" -gt 0 ]; then
  if command -v timeout >/dev/null 2>&1; then
    RUN_CMD=(timeout --signal=INT "$TIMEOUT" "${CMD[@]}")
  else
    note "--timeout requested but 'timeout' not found; running without it"
  fi
fi

if [ "$DRY_RUN" -eq 1 ]; then
  printf '[dry-run]'; printf ' %q' "${RUN_CMD[@]}"; echo
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

# Precondition: refuse to start on a dirty working tree, which would make the
# template's branch setup fail mid-run.
if [ "$ALLOW_DIRTY" -eq 0 ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if [ -n "$(git status --porcelain)" ]; then
    die "working tree is dirty; commit/stash first or pass --allow-dirty"
  fi
fi

# Confirmation gate: this run autonomously implements AND merges the issue.
# Skip when --yes/MX_AGENT_YES is set or stdin is not a terminal (unattended).
if [ "$ASSUME_YES" -eq 0 ] && [ -t 0 ]; then
  printf '>> About to autonomously implement and MERGE issue #%s. Continue? [y/N] ' "$ISSUE" >&2
  read -r reply
  case "$reply" in
    [Yy]|[Yy][Ee][Ss]) ;;
    *) die "aborted" ;;
  esac
fi

# Run pi, optionally teeing the transcript to a per-issue log file.
LOG_FILE=""
if [ -n "$LOG_DIR" ]; then
  mkdir -p "$LOG_DIR"
  LOG_FILE="$LOG_DIR/issue-$ISSUE-$(date +%Y%m%dT%H%M%S).log"
  note "logging transcript to $LOG_FILE"
fi

note "running /issue $ISSUE headlessly via $RUNNER ($RUNNER_BIN)"
set +e
if [ -n "$LOG_FILE" ]; then
  "${RUN_CMD[@]}" 2>&1 | tee "$LOG_FILE"
  run_rc=${PIPESTATUS[0]}
else
  "${RUN_CMD[@]}"
  run_rc=$?
fi
set -e

# Verify the outcome against GitHub: a real success means the issue is CLOSED.
if [ "$VERIFY" -eq 1 ]; then
  state="$(issue_state)"
  if [ "$state" = "CLOSED" ]; then
    note "verified: issue #$ISSUE is CLOSED"
    exit 0
  fi
  die "issue #$ISSUE is still ${state} after the run (${RUNNER} exit ${run_rc}); treating as failure"
fi

exit "$run_rc"
