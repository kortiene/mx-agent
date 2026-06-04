#!/bin/sh
# Mirror the wiki/ folder to this repo's GitHub wiki (<repo>.wiki.git).
#
# Designed to run as a pre-push hook (install with scripts/install-wiki-hook.sh)
# but can also be run by hand. When run as a hook it reads the push refs from
# stdin and only syncs when 'main' is among them, mirroring the wiki/ content
# from the exact commit being pushed. Run manually with --force to sync the
# current HEAD's wiki/ regardless of stdin.
#
# Wiki sync NEVER blocks a push: any failure prints a warning and exits 0.
#
# The wiki remote is derived from `origin` (e.g. git@github.com:org/repo.git ->
# git@github.com:org/repo.wiki.git). Override with the MX_WIKI_REMOTE env var.

set -u

REPO_ROOT=$(git rev-parse --show-toplevel) || exit 0
WIKI_CACHE="$REPO_ROOT/.git/wiki-sync" # cached clone of the wiki repo

# --- derive the wiki remote from origin (or honor an override) ---------------
if [ -n "${MX_WIKI_REMOTE:-}" ]; then
	WIKI_REMOTE="$MX_WIKI_REMOTE"
else
	ORIGIN_URL=$(git remote get-url origin 2>/dev/null) || {
		echo "sync-wiki: no 'origin' remote and MX_WIKI_REMOTE unset, skipping" >&2
		exit 0
	}
	case "$ORIGIN_URL" in
	*.git) WIKI_REMOTE="${ORIGIN_URL%.git}.wiki.git" ;;
	*) WIKI_REMOTE="${ORIGIN_URL}.wiki.git" ;;
	esac
fi

# --- decide which commit's wiki/ to publish ----------------------------------
PUSH_SHA=""
if [ "${1:-}" = "--force" ]; then
	PUSH_SHA=$(git rev-parse HEAD)
else
	# pre-push stdin lines: <local ref> <local sha> <remote ref> <remote sha>.
	# All four fields must be named to consume the line; local_ref/remote_sha
	# are part of git's protocol but unused here.
	# shellcheck disable=SC2034
	while read -r local_ref local_sha remote_ref remote_sha; do
		case "$remote_ref" in
		refs/heads/main) PUSH_SHA="$local_sha" ;;
		esac
	done
fi
# empty or zero sha (branch deletion / main not pushed) => nothing to do
case "$PUSH_SHA" in
"" | 0000000000000000000000000000000000000000) exit 0 ;;
esac

# --- extract wiki/ from that commit ------------------------------------------
git cat-file -e "$PUSH_SHA:wiki" 2>/dev/null || exit 0 # no wiki/ in that commit

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
if ! git archive "$PUSH_SHA" wiki | tar -x -C "$STAGE" 2>/dev/null; then
	echo "sync-wiki: could not extract wiki/ from $PUSH_SHA, skipping" >&2
	exit 0
fi

echo "sync-wiki: syncing wiki/ -> $WIKI_REMOTE"

# --- refresh the cached wiki clone -------------------------------------------
if [ -d "$WIKI_CACHE/.git" ]; then
	git -C "$WIKI_CACHE" fetch --quiet origin 2>/dev/null || {
		echo "sync-wiki: wiki fetch failed, skipping" >&2
		exit 0
	}
else
	rm -rf "$WIKI_CACHE"
	git clone --quiet "$WIKI_REMOTE" "$WIKI_CACHE" 2>/dev/null || {
		echo "sync-wiki: wiki clone failed (is the wiki initialized?), skipping" >&2
		exit 0
	}
fi

# GitHub wikis default to 'master'; detect to be safe.
DEFAULT=$(git -C "$WIKI_CACHE" symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null | sed 's@^origin/@@')
DEFAULT=${DEFAULT:-master}
git -C "$WIKI_CACHE" reset --quiet --hard "origin/$DEFAULT" 2>/dev/null || true

# --- mirror the .md files (deletes propagate) --------------------------------
find "$WIKI_CACHE" -maxdepth 1 -name '*.md' -delete
cp "$STAGE"/wiki/*.md "$WIKI_CACHE"/ 2>/dev/null

if [ -z "$(git -C "$WIKI_CACHE" status --porcelain)" ]; then
	echo "sync-wiki: wiki already up to date"
	exit 0
fi

SHORT=$(git rev-parse --short "$PUSH_SHA")
git -C "$WIKI_CACHE" add -A
git -C "$WIKI_CACHE" commit --quiet -m "Sync wiki from main repo ($SHORT)"
if git -C "$WIKI_CACHE" push --quiet origin "HEAD:$DEFAULT" 2>/dev/null; then
	echo "sync-wiki: wiki synced ($SHORT)"
else
	echo "sync-wiki: wiki push failed (continuing) " >&2
fi

exit 0
