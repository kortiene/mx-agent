#!/usr/bin/env bash
# issues.sh — process several GitHub issues in order via scripts/issue.sh.
#
# Runs the headless `/issue` workflow for each issue number you pass, one at a
# time, in the given order. Useful for working a milestone backlog where later
# issues depend on earlier ones.
#
# Usage:
#   scripts/issues.sh <spec...> [-- <extra flags for issue.sh>]
#
# A <spec> is an issue number (e.g. 15) or an inclusive range (15-18 or 15..18).
# Specs are expanded left to right, preserving order and duplicates.
#
# Each issue is verified against GitHub by issue.sh: a run only counts as done
# if the issue ends up CLOSED. Already-closed issues are skipped, so a batch is
# safely resumable just by re-running it.
#
# Options:
#   --keep-going       Continue to the next issue even if one fails
#                      (default: stop at the first failure).
#   --start <number>   Skip ahead: ignore issues before this number in the
#                      expanded list (resume an interrupted run).
#   --delay <seconds>  Sleep this many seconds between issues (default: 0).
#   --log-dir <dir>    Forward --log-dir to issue.sh so each run is captured.
#   --dry-run          Print what would run; do not invoke issue.sh.
#   --                 Everything after is forwarded verbatim to issue.sh
#                      (e.g. --json, --model sonnet:high, --dry-run).
#   -h, --help         Show this help.
#
# Examples:
#   scripts/issues.sh 15 16 17
#   scripts/issues.sh 15-22 --json
#   scripts/issues.sh 15..30 --keep-going -- --model sonnet:high
#   scripts/issues.sh 15-30 --start 21        # resume from #21

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISSUE_SH="$HERE/issue.sh"

KEEP_GOING=0
START=0
DELAY=0
DRY_RUN=0
PASSTHRU=()
SPECS=()

die() { echo "error: $*" >&2; exit 1; }
note() { echo ">> $*" >&2; }
# Print the leading comment block (after the shebang) as help text.
usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

LOG_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --keep-going) KEEP_GOING=1 ;;
    --start) shift; START="${1:?--start needs a value}" ;;
    --delay) shift; DELAY="${1:?--delay needs a value}" ;;
    --log-dir) shift; LOG_DIR="${1:?--log-dir needs a value}" ;;
    --dry-run) DRY_RUN=1 ;;
    --) shift; PASSTHRU+=("$@"); break ;;
    -*) die "unknown option: $1" ;;
    *) SPECS+=("$1") ;;
  esac
  shift
done

[ "${#SPECS[@]}" -gt 0 ] || { usage; exit 2; }
[ -x "$ISSUE_SH" ] || die "issue runner not found or not executable: $ISSUE_SH"
[[ "$START" =~ ^[0-9]+$ ]] || die "--start must be a number"
[[ "$DELAY" =~ ^[0-9]+$ ]] || die "--delay must be a number"

# Expand specs (numbers and N-M / N..M ranges) into an ordered issue list.
ISSUES=()
for spec in "${SPECS[@]}"; do
  if [[ "$spec" =~ ^([0-9]+)(-|\.\.)([0-9]+)$ ]]; then
    lo="${BASH_REMATCH[1]}"; hi="${BASH_REMATCH[3]}"
    if [ "$lo" -le "$hi" ]; then
      for ((n=lo; n<=hi; n++)); do ISSUES+=("$n"); done
    else
      for ((n=lo; n>=hi; n--)); do ISSUES+=("$n"); done
    fi
  elif [[ "$spec" =~ ^[0-9]+$ ]]; then
    ISSUES+=("$spec")
  else
    die "invalid issue spec: $spec (want N, N-M, or N..M)"
  fi
done

# Apply --start filter (resume).
if [ "$START" -gt 0 ]; then
  FILTERED=()
  for n in "${ISSUES[@]}"; do
    [ "$n" -ge "$START" ] && FILTERED+=("$n")
  done
  ISSUES=("${FILTERED[@]}")
fi

[ "${#ISSUES[@]}" -gt 0 ] || die "no issues to process after expansion/filtering"

# Forward --log-dir to each issue.sh run.
[ -n "$LOG_DIR" ] && PASSTHRU=(--log-dir "$LOG_DIR" "${PASSTHRU[@]}")

note "processing ${#ISSUES[@]} issue(s) in order: ${ISSUES[*]}"

# Print the running summary; used both on normal completion and on interrupt.
print_summary() {
  note "summary: ${#DONE[@]} completed, ${#FAILED[@]} failed"
  [ "${#DONE[@]}" -eq 0 ]   || note "  completed: ${DONE[*]}"
  [ "${#FAILED[@]}" -eq 0 ] || note "  failed:    ${FAILED[*]}"
}

FAILED=()
DONE=()
trap 'echo >&2; note "interrupted"; print_summary; exit 130' INT TERM

total="${#ISSUES[@]}"
i=0
for n in "${ISSUES[@]}"; do
  i=$((i + 1))
  echo >&2
  note "[$i/$total] === issue #$n ==="

  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run]'; printf ' %q' "$ISSUE_SH" "$n" "${PASSTHRU[@]}"; echo
    DONE+=("$n")
    continue
  fi

  if "$ISSUE_SH" "$n" "${PASSTHRU[@]}"; then
    note "[$i/$total] issue #$n finished"
    DONE+=("$n")
  else
    code=$?
    note "[$i/$total] issue #$n FAILED (exit $code)"
    FAILED+=("$n")
    if [ "$KEEP_GOING" -eq 0 ]; then
      note "stopping (use --keep-going to continue past failures)"
      break
    fi
  fi

  if [ "$DELAY" -gt 0 ] && [ "$i" -lt "$total" ]; then
    sleep "$DELAY"
  fi
done

echo >&2
print_summary
[ "${#FAILED[@]}" -eq 0 ] || exit 1
exit 0
