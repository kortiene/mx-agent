/**
 * The deny-by-default environment allowlist for runner children (PLAN.md D5),
 * ported from adw/_exec.py:97-141 safe_subprocess_env.
 *
 * This is the load-bearing secret boundary: the env object built here is the
 * ONLY environment any runner child may receive — passed as claude
 * options.env / codex CodexOptions.env (verified replace semantics) or as the
 * spawn env for opencode/pi. The parent environment is NEVER copied
 * wholesale, so GH_TOKEN, Matrix tokens, device keys, and any future secret
 * are withheld by default. Runner modules must never spread process.env
 * (enforced by scripts/check-adw-sdlc-env.sh and the env-isolation tests).
 */

import type { RunnerId } from './invoker.js';

/**
 * Base variables every runner legitimately needs (adw/_exec.py:97-112).
 * PATH/HOME stay here so each SDK can locate and spawn its runtime
 * (PLAN.md Section 4.3-1).
 */
export const BASE_ENV_ALLOW = [
  'HOME',
  'USER',
  'PATH',
  'SHELL',
  'TERM',
  'LANG',
  'LC_ALL',
  'TMPDIR',
  'ANTHROPIC_API_KEY',
  'PI_BIN',
  'CLAUDE_BIN',
  'CLAUDE_CODE_PATH',
  'PI_MODEL',
  'PI_THINKING',
] as const;

/** Never forwarded to the agent, even via extraAllow (adw/_exec.py:115). */
export const ENV_DENY_PREFIXES = ['MATRIX_', 'MX_AGENT_'] as const;

/**
 * Per-runner credential keys layered on top of the base allowlist
 * (PLAN.md Section 4.3). Keys already in BASE_ENV_ALLOW are not repeated.
 */
export const RUNNER_ENV_ALLOW: Record<RunnerId, readonly string[]> = {
  claude: ['ANTHROPIC_AUTH_TOKEN'],
  codex: ['CODEX_API_KEY', 'OPENAI_API_KEY'],
  opencode: ['OPENAI_API_KEY', 'OPENCODE_SERVER_PASSWORD'],
  pi: ['OPENAI_API_KEY'],
};

export interface SafeEnvOptions {
  /**
   * Phased mode always passes false: the orchestrator performs all gh work,
   * so the agent never sees GH_TOKEN (one-shot mode is the only legitimate
   * true, mirroring adw/_exec.py:118-126).
   */
  allowGhToken: boolean;
  /** Layer this runner's credential keys (RUNNER_ENV_ALLOW) onto the base. */
  runner?: RunnerId;
  /** Extra keys to forward; deny-prefixed keys are silently dropped. */
  extraAllow?: readonly string[];
  /** Parent environment to read from (tests inject a poisoned copy). */
  source?: Record<string, string | undefined>;
}

/**
 * Build the allowlist environment for a runner child. Only allowlisted
 * variables present in the source environment are forwarded; variables
 * matching ENV_DENY_PREFIXES are never forwarded, even when explicitly
 * requested via extraAllow.
 */
export function safeSubprocessEnv(options: SafeEnvOptions): Record<string, string> {
  const source = options.source ?? process.env;

  const allow: string[] = [...BASE_ENV_ALLOW];
  if (options.allowGhToken) {
    allow.push('GH_TOKEN', 'GH_BIN');
  }
  if (options.runner !== undefined) {
    allow.push(...RUNNER_ENV_ALLOW[options.runner]);
  }
  for (const key of options.extraAllow ?? []) {
    if (!ENV_DENY_PREFIXES.some((prefix) => key.startsWith(prefix))) {
      allow.push(key);
    }
  }

  const env: Record<string, string> = {};
  for (const key of allow) {
    const value = source[key];
    if (value !== undefined) {
      env[key] = value;
    }
  }
  // Python adds PYTHONUNBUFFERED=1 for its CLI children; the TS engine drives
  // no Python child, so that key is deliberately not carried over.
  return env;
}
