#!/usr/bin/env bash
# Lint gate for the adw_sdlc secret boundary (PLAN.md D5 / Sections 4 & 9).
#
# Every runner child's environment must be built exclusively by
# safeSubprocessEnv(); spreading process.env into an SDK/spawn env would
# silently leak GH_TOKEN / MATRIX_* / MX_AGENT_* to an agent with shell
# access. This gate fails CI the moment any runner module spreads
# process.env, complementing the env-isolation unit tests.
set -euo pipefail

cd "$(dirname "$0")/.."
runners_dir="adw_sdlc/src/runners"

# Scaffold-tolerant: pass (quietly) until the first runner adapter exists.
if [ ! -d "$runners_dir" ]; then
  echo "ok: $runners_dir does not exist yet; nothing to check"
  exit 0
fi

if grep -rnE '\.\.\.[[:space:]]*process\.env' "$runners_dir" --include='*.ts'; then
  echo "error: runner modules must never spread process.env; build child envs via safeSubprocessEnv() only" >&2
  exit 1
fi

echo "ok: no process.env spread in $runners_dir"
