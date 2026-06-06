#!/usr/bin/env bash
# work_issue.sh — start (or inspect) work on a GitHub issue by number.
#
# Given an issue number, this command:
#   1. Fetches the issue (title, body, labels, milestone, state).
#   2. Derives a branch name from the issue type label and title.
#   3. Creates/checks out that branch from an up-to-date base branch.
#   4. Assigns the issue to the current user.
#   5. Moves the issue's project board card to "In Progress" (best effort).
#   6. Prints the scope and acceptance criteria for implementation.
#
# Usage:
#   adw/work_issue.sh <issue-number> [options]
#
# Options:
#   --dry-run        Show what would happen; make no git/GitHub changes.
#   --print          Only print issue context (implies --dry-run).
#   --base <branch>  Base branch to fork from (default: main).
#   --no-branch      Do not create/switch a git branch.
#   --no-assign      Do not assign the issue to the current user.
#   --no-status      Do not update the project board status.
#   --status <name>  Project Status option to set (default: "In Progress").
#   -h, --help       Show this help.
#
# Requirements: gh (authenticated, with `project` scope for board updates), jq, git.

set -euo pipefail

PROJECT_TITLE="${PROJECT_TITLE:-mx-agent roadmap}"
BASE_BRANCH="main"
TARGET_STATUS="In Progress"
DRY_RUN=0
PRINT_ONLY=0
DO_BRANCH=1
DO_ASSIGN=1
DO_STATUS=1
ISSUE=""

die() { echo "error: $*" >&2; exit 1; }
note() { echo ">> $*"; }

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --dry-run) DRY_RUN=1 ;;
    --print) PRINT_ONLY=1; DRY_RUN=1 ;;
    --no-branch) DO_BRANCH=0 ;;
    --no-assign) DO_ASSIGN=0 ;;
    --no-status) DO_STATUS=0 ;;
    --base) shift; BASE_BRANCH="${1:?--base needs a value}" ;;
    --status) shift; TARGET_STATUS="${1:?--status needs a value}" ;;
    -*) die "unknown option: $1" ;;
    *) [ -z "$ISSUE" ] || die "unexpected argument: $1"; ISSUE="$1" ;;
  esac
  shift
done

[ -n "$ISSUE" ] || { usage; exit 2; }
[[ "$ISSUE" =~ ^[0-9]+$ ]] || die "issue must be a number, got: $ISSUE"
command -v gh >/dev/null 2>&1 || die "gh CLI not found"
command -v jq >/dev/null 2>&1 || die "jq not found"
command -v git >/dev/null 2>&1 || die "git not found"

REPO="${REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
OWNER="${OWNER:-${REPO%%/*}}"

# 1. Fetch issue (use --json to avoid the deprecated projectCards GraphQL path).
ISSUE_JSON="$(gh issue view "$ISSUE" --repo "$REPO" \
  --json number,title,body,labels,milestone,state,url,assignees)"

TITLE="$(jq -r '.title' <<<"$ISSUE_JSON")"
STATE="$(jq -r '.state' <<<"$ISSUE_JSON")"
URL="$(jq -r '.url' <<<"$ISSUE_JSON")"
MILESTONE="$(jq -r '.milestone.title // "none"' <<<"$ISSUE_JSON")"
mapfile -t LABELS < <(jq -r '.labels[].name' <<<"$ISSUE_JSON")

# 2. Derive branch prefix from type label, slug from the title.
prefix="feat"
for l in "${LABELS[@]}"; do
  case "$l" in
    type:bug) prefix="fix" ;;
    type:docs) prefix="docs" ;;
    type:ci) prefix="ci" ;;
    type:testing) prefix="test" ;;
  esac
done

# Strip a leading "Phase issue N:" prefix, then slugify.
slug_src="$(sed -E 's/^Phase issue [0-9]+: *//' <<<"$TITLE")"
slug="$(printf '%s' "$slug_src" \
  | tr '[:upper:]' '[:lower:]' \
  | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//' \
  | cut -c1-40 | sed -E 's/-+$//')"
BRANCH="${prefix}/${ISSUE}-${slug}"

# Context output.
cat <<EOF

================ issue #$ISSUE ================
Title:     $TITLE
State:     $STATE
Milestone: $MILESTONE
Labels:    ${LABELS[*]}
URL:       $URL
Branch:    $BRANCH
Base:      $BASE_BRANCH
===============================================
EOF

echo
echo "----- scope & acceptance criteria -----"
jq -r '.body' <<<"$ISSUE_JSON" \
  | sed -n '/^## Backlog Entry/,$p' \
  | sed '1d' \
  | sed '/^$/{N;/^\n$/d}'
echo "---------------------------------------"
echo

if [ "$STATE" = "CLOSED" ]; then
  echo "warning: issue #$ISSUE is CLOSED." >&2
fi

if [ "$PRINT_ONLY" -eq 1 ]; then
  exit 0
fi

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] $*"
  else
    note "$*"
    "$@"
  fi
}

# 3. Branch setup from an up-to-date base.
if [ "$DO_BRANCH" -eq 1 ]; then
  if [ "$DRY_RUN" -eq 0 ] && [ -n "$(git status --porcelain)" ]; then
    die "working tree is dirty; commit or stash before starting an issue"
  fi
  run git fetch origin --quiet
  if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
    run git switch "$BRANCH"
  else
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "[dry-run] git switch -c $BRANCH origin/$BASE_BRANCH"
    else
      run git switch -c "$BRANCH" "origin/$BASE_BRANCH"
    fi
  fi
fi

# 4. Assign the issue to the current user.
if [ "$DO_ASSIGN" -eq 1 ]; then
  run gh issue edit "$ISSUE" --repo "$REPO" --add-assignee @me
fi

# 5. Move the project board card to the target status (best effort).
set_status() {
  local proj_json item_id field_id option_id proj_id
  proj_json="$(gh project view 1 --owner "$OWNER" --format json 2>/dev/null || true)"
  proj_id="$(jq -r '.id // empty' <<<"$proj_json")"
  [ -n "$proj_id" ] || { echo "note: project board not found; skipping status" >&2; return 0; }

  item_id="$(gh project item-list 1 --owner "$OWNER" --format json --limit 300 \
    | jq -r --argjson n "$ISSUE" '.items[] | select(.content.number==$n) | .id' | head -n1)"
  [ -n "$item_id" ] || { echo "note: issue not on board; skipping status" >&2; return 0; }

  field_id="$(gh project field-list 1 --owner "$OWNER" --format json \
    | jq -r '.fields[] | select(.name=="Status") | .id')"
  option_id="$(gh project field-list 1 --owner "$OWNER" --format json \
    | jq -r --arg s "$TARGET_STATUS" '.fields[] | select(.name=="Status") | .options[] | select(.name==$s) | .id')"
  [ -n "$option_id" ] || { echo "note: status option '$TARGET_STATUS' not found; skipping" >&2; return 0; }

  gh project item-edit --id "$item_id" --project-id "$proj_id" \
    --field-id "$field_id" --single-select-option-id "$option_id" >/dev/null
  note "set board status of #$ISSUE -> $TARGET_STATUS"
}

if [ "$DO_STATUS" -eq 1 ]; then
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] set board status of #$ISSUE -> $TARGET_STATUS"
  else
    set_status || echo "note: could not update board status" >&2
  fi
fi

echo
note "ready to implement #$ISSUE on branch '$BRANCH'"
