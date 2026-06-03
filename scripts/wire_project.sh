#!/usr/bin/env bash
# Create (or reuse) a GitHub Projects v2 board and add all roadmap issues to it.
#
# Requirements:
#   - gh CLI authenticated with a token that has `project` + `repo` scopes:
#       gh auth login --scopes "repo,project,read:org"
#     or: export GH_TOKEN=<PAT with project,repo>
#   - run from anywhere inside the repo
#
# Idempotent: reuses an existing project with the same title and skips issues
# already on the board.

set -euo pipefail

PROJECT_TITLE="${PROJECT_TITLE:-mx-agent roadmap}"
REPO="${REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
OWNER="${OWNER:-${REPO%%/*}}"

echo "Repo:    $REPO"
echo "Owner:   $OWNER"
echo "Project: $PROJECT_TITLE"

# 1. Find or create the project (owned by the user/org that owns the repo).
PROJECT_NUMBER="$(
  gh project list --owner "$OWNER" --format json \
    | jq -r --arg t "$PROJECT_TITLE" '.projects[] | select(.title==$t) | .number' \
    | head -n1
)"

if [ -z "${PROJECT_NUMBER:-}" ]; then
  echo "Creating project..."
  PROJECT_NUMBER="$(
    gh project create --owner "$OWNER" --title "$PROJECT_TITLE" --format json | jq -r '.number'
  )"
else
  echo "Reusing existing project #$PROJECT_NUMBER"
fi

PROJECT_URL="$(gh project view "$PROJECT_NUMBER" --owner "$OWNER" --format json | jq -r '.url')"
echo "Project URL: $PROJECT_URL"
echo "PROJECT_URL=$PROJECT_URL"

# 2. Add every roadmap issue (label roadmap:auto) to the project.
echo "Collecting roadmap issues..."
mapfile -t ISSUE_URLS < <(
  gh issue list --repo "$REPO" --label roadmap:auto --state all --limit 500 \
    --json url -q '.[].url'
)
echo "Found ${#ISSUE_URLS[@]} roadmap issues"

for url in "${ISSUE_URLS[@]}"; do
  if gh project item-add "$PROJECT_NUMBER" --owner "$OWNER" --url "$url" >/dev/null 2>&1; then
    echo "added: $url"
  else
    echo "skip (already present or error): $url"
  fi
done

echo "Done."
echo
echo "Next: store the project URL as a repo variable so new issues auto-add:"
echo "  gh variable set PROJECT_URL --repo $REPO --body \"$PROJECT_URL\""
