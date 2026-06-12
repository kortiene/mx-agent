/**
 * Tier→model routing per runner (PLAN.md Section 6), ported from
 * adw/_phases.py:55-71 (PHASE_TIER / TIER_MODELS) and model_for_phase
 * (adw/_phases.py:88-97). Override precedence is preserved verbatim:
 * --model > MX_AGENT_MODEL_<PHASE> > tier default.
 */

import type { RunnerId } from './invoker.js';

export type Tier = 'cheap' | 'mid' | 'capable';

/** Phase → model tier (adw/_phases.py:55-65). Unknown phases resolve as 'mid'. */
export const PHASE_TIER: Record<string, Tier> = {
  classify: 'cheap',
  plan: 'capable',
  implement: 'capable',
  tests: 'mid',
  resolve: 'mid',
  e2e: 'mid',
  review: 'capable',
  patch: 'capable',
  document: 'mid',
};

/**
 * Tier → concrete model id, per runner.
 *
 * - claude: exact current Claude IDs (PLAN.md Section 6).
 * - pi: bare model names, matching the Python TIER_MODELS verbatim — pi
 *   accepts them and users override via --model / MX_AGENT_MODEL_<PHASE>.
 * - codex: verified current in roadmap step 7 (Codex models endpoint cache
 *   of 2026-05-31 + the OpenAI pricing docs): gpt-5.4-mini / gpt-5.4 /
 *   gpt-5.5, all supported_in_api with effort low|medium|high|xhigh. The
 *   newest generations dropped the `-codex` suffix (last was gpt-5.3-codex).
 * - opencode: provider/model strings; Anthropic models by default.
 */
export const TIER_MODELS: Record<RunnerId, Record<Tier, string>> = {
  claude: { cheap: 'claude-haiku-4-5', mid: 'claude-sonnet-4-6', capable: 'claude-opus-4-8' },
  pi: { cheap: 'haiku', mid: 'sonnet', capable: 'opus' },
  codex: { cheap: 'gpt-5.4-mini', mid: 'gpt-5.4', capable: 'gpt-5.5' },
  opencode: {
    cheap: 'anthropic/claude-haiku-4-5',
    mid: 'anthropic/claude-sonnet-4-6',
    capable: 'anthropic/claude-opus-4-8',
  },
};

/**
 * The classify phase runs on the shared Anthropic SDK structured call with
 * this model regardless of the selected runner (PLAN.md D1).
 */
export const CLASSIFY_MODEL = 'claude-haiku-4-5';

export interface ModelOverrides {
  /** --model: applies to every phase when set. */
  cliModel?: string;
  /** Environment for MX_AGENT_MODEL_<PHASE> lookups; defaults to process.env. */
  env?: Record<string, string | undefined>;
}

/** Resolve the model for `phase` on `runner`: --model > MX_AGENT_MODEL_<PHASE> > tier default. */
export function modelForPhase(phase: string, runner: RunnerId, overrides: ModelOverrides = {}): string {
  if (overrides.cliModel) {
    return overrides.cliModel;
  }
  const env = overrides.env ?? process.env;
  const envOverride = env[`MX_AGENT_MODEL_${phase.toUpperCase()}`];
  if (envOverride) {
    return envOverride;
  }
  const tier = PHASE_TIER[phase] ?? 'mid';
  return TIER_MODELS[runner][tier];
}
