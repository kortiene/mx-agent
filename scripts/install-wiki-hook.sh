#!/bin/sh
# Install the wiki-sync pre-push hook for this clone.
#
# The hook delegates to scripts/sync-wiki.sh, which mirrors the wiki/ folder to
# this repo's GitHub wiki whenever 'main' is pushed. Re-run this after cloning;
# git hooks are local and are not copied by `git clone`.
#
# Respects core.hooksPath if you use a managed hooks directory.

set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)

HOOKS_DIR=$(git config --get core.hooksPath || true)
if [ -z "$HOOKS_DIR" ]; then
	HOOKS_DIR="$REPO_ROOT/.git/hooks"
fi
# resolve relative core.hooksPath against the repo root
case "$HOOKS_DIR" in
/*) : ;;
*) HOOKS_DIR="$REPO_ROOT/$HOOKS_DIR" ;;
esac

mkdir -p "$HOOKS_DIR"
HOOK="$HOOKS_DIR/pre-push"

if [ -e "$HOOK" ] && ! grep -q 'sync-wiki.sh' "$HOOK" 2>/dev/null; then
	echo "install-wiki-hook: a pre-push hook already exists at:"
	echo "  $HOOK"
	echo "Refusing to overwrite it. Add this line to it manually instead:"
	echo "  \"\$(git rev-parse --show-toplevel)\"/scripts/sync-wiki.sh \"\$@\" < /dev/stdin"
	exit 1
fi

cat >"$HOOK" <<'EOF'
#!/bin/sh
# Auto-installed by scripts/install-wiki-hook.sh — mirrors wiki/ to the GitHub
# wiki on pushes to main. Edit scripts/sync-wiki.sh to change the behavior.
exec "$(git rev-parse --show-toplevel)/scripts/sync-wiki.sh" "$@"
EOF
chmod +x "$HOOK"

# make sure the delegated script is executable too
chmod +x "$REPO_ROOT/scripts/sync-wiki.sh" 2>/dev/null || true

echo "install-wiki-hook: installed pre-push hook at $HOOK"
echo "install-wiki-hook: it will mirror wiki/ to the GitHub wiki on 'git push' of main."
