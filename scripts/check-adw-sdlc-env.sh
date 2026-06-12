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

# Inside runner modules, never hand the parent env to a child under the env:
# key either (a cast like `env: process.env as Record<string,string>` would
# satisfy tsc). The orchestrator legitimately holds process.env as the SOURCE
# safeSubprocessEnv reads from (OrchestratorDeps.env), so this stays scoped
# to where child envs are constructed.
if grep -rnE 'env[[:space:]]*:[[:space:]]*process\.env' "$runners_dir" --include='*.ts'; then
  echo "error: never pass process.env as a child env; build it via safeSubprocessEnv() only" >&2
  exit 1
fi

# Codex always-pass-env gate (PLAN.md Sections 4.3-2 / 9): omitting
# CodexOptions.env flips the SDK from no-inherit to full process.env inherit
# (@openai/codex-sdk 0.139.0 dist/index.js:234-239). The spawn-level unit
# test asserts the SDK-built child env; this tripwire catches a bad
# construction even before tests run. It FAILS CLOSED: every `new Codex`
# anywhere in adw_sdlc/src must use the one canonical shape — an inline
# object literal whose FIRST key is env — and the class must never be
# aliased (an alias would evade the pattern).
# shellcheck disable=SC2016  # $ARGV/$head are perl variables, not shell expansions
codex_violations=$(find adw_sdlc/src -name '*.ts' -print0 | xargs -0 perl -0777 -ne '
  print "$ARGV: aliasing the Codex class is not allowed (it evades this gate)\n"
    if /\bCodex\s+as\s+\w/ || /=\s*Codex\s*[;,)\s]/;
  while (/\bnew\s+Codex\b(?=(.{0,80}))/gs) {
    my $head = $1;
    $head =~ s/\s+/ /g;
    print "$ARGV: new Codex must take an inline literal starting with env: (saw: new Codex$head)\n"
      unless $head =~ /^\s*\(\s*\{\s*env\s*:/;
  }')
if [ -n "$codex_violations" ]; then
  echo "$codex_violations" >&2
  echo "error: the codex adapter must ALWAYS pass CodexOptions.env (omission inherits all of process.env)" >&2
  exit 1
fi

# opencode server-spawn gate (PLAN.md Sections 4.3-3 / 9): the SDK's own
# createOpencodeServer/createOpencodeTui/createOpencode hardcode a full
# parent-process-env spread onto the child (@opencode-ai/sdk 1.17.3
# dist/v2/server.js), so the adapter must self-spawn `opencode serve` with
# the allowlist. Ban CALLING or IMPORTING the leaking helpers (and the
# module subpaths that export them) anywhere in adw_sdlc/src; prose mentions
# in comments stay legal.
if grep -rnE "createOpencode(Server|Tui)?[[:space:]]*\(|import[^;]*createOpencode(Server|Tui)\b|from[[:space:]]+'@opencode-ai/sdk(/v2)?(/server)?'" adw_sdlc/src --include='*.ts'; then
  echo "error: never use the SDK's createOpencodeServer/createOpencodeTui/createOpencode or the server-exporting subpaths (they spread process.env); import '@opencode-ai/sdk/v2/client' and self-spawn opencode serve with the allowlist env" >&2
  exit 1
fi

echo "ok: no process.env spread/handoff in adw_sdlc/src; every new Codex(...) passes env first; no createOpencodeServer"
