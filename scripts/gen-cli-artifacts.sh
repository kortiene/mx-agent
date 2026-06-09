#!/usr/bin/env bash
# gen-cli-artifacts.sh — generate shell completions and man pages for mx-agent.
#
# Emits completion scripts (bash/zsh/fish/elvish/powershell) and roff man pages
# directly from the binary's clap command tree, so packaged artifacts never
# drift from the CLI. Used locally by packagers and by the release workflow.
#
# Usage:
#   scripts/gen-cli-artifacts.sh [OUT_DIR] [MX_AGENT_BIN]
#
# Arguments:
#   OUT_DIR       Output directory (default: dist). Creates OUT_DIR/completions
#                 and OUT_DIR/man.
#   MX_AGENT_BIN  Path to a prebuilt mx-agent binary. If omitted, the script
#                 falls back to `cargo run -q -p mx-agent-cli --`.
#
# Examples:
#   scripts/gen-cli-artifacts.sh                       # -> dist/{completions,man}
#   scripts/gen-cli-artifacts.sh out target/release/mx-agent

set -euo pipefail

out_dir="${1:-dist}"
bin="${2:-}"

if [ -n "$bin" ]; then
  run() { "$bin" "$@"; }
else
  run() { cargo run -q -p mx-agent-cli -- "$@"; }
fi

completions_dir="$out_dir/completions"
man_dir="$out_dir/man"
mkdir -p "$completions_dir" "$man_dir"

# Completion file naming follows each shell's conventional discovery layout.
run generate completions bash       > "$completions_dir/mx-agent.bash"
run generate completions zsh        > "$completions_dir/_mx-agent"
run generate completions fish       > "$completions_dir/mx-agent.fish"
run generate completions elvish     > "$completions_dir/mx-agent.elv"
run generate completions powershell > "$completions_dir/_mx-agent.ps1"

run generate man --dir "$man_dir"

echo "mx-agent: wrote completions to $completions_dir and man pages to $man_dir"
ls -1 "$completions_dir" "$man_dir"
