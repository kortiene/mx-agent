#!/usr/bin/env bash
# issue.sh — run the `/issue` workflow headlessly via the pi CLI.
#
# This is the non-interactive equivalent of typing `/issue <number> [notes]`
# in pi's editor. It expands the same prompt template (.pi/prompts/issue.md),
# substituting the issue number and notes exactly as pi would, then feeds the
# result to `pi -p` (print mode) so the agent implements the issue end-to-end:
# branch, code, test, PR, watch CI, merge.
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
#   --print-prompt     Expand the template and print it; do not run pi.
#   --dry-run          Print the exact pi command; do not run it.
#   --                 Everything after is passed verbatim to pi.
#   -h, --help         Show this help.
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
PRINT_PROMPT=0
DRY_RUN=0
ARGS=()

die() { echo "error: $*" >&2; exit 1; }
note() { echo ">> $*" >&2; }
usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; }

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

note "running /issue $ISSUE headlessly via $PI_BIN (session: $SESSION_NAME)"
exec "${CMD[@]}"
