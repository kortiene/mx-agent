/**
 * Price table for TOKEN-ONLY backends (PLAN.md D1 / Section 6).
 *
 * claude, opencode, and pi report dollars natively, so they never consult
 * this table. It exists only for backends that report tokens without cost:
 * the shared Anthropic-SDK classify call and the codex tiers (verified in
 * roadmap step 7). A missing or stale entry yields a null cost, which is
 * non-fatal: it only disables the parent-side budget gate for that backend.
 */

import type { PhaseUsage } from './invoker.js';

export interface PriceEntry {
  inputUsdPerMTok: number;
  outputUsdPerMTok: number;
  cacheReadUsdPerMTok?: number;
  cacheWrite5mUsdPerMTok?: number;
}

/**
 * Verified 2026-06: haiku against the Claude pricing reference ($1/$5, cache
 * read 0.1x, 5m write 1.25x); the codex tiers against the OpenAI API pricing
 * docs (developers.openai.com/api/docs/pricing, standard tier). OpenAI does
 * not bill cache writes, so the codex entries carry no cacheWrite rate.
 */
export const PRICES: Record<string, PriceEntry> = {
  'claude-haiku-4-5': {
    inputUsdPerMTok: 1.0,
    outputUsdPerMTok: 5.0,
    cacheReadUsdPerMTok: 0.1,
    cacheWrite5mUsdPerMTok: 1.25,
  },
  'gpt-5.4-mini': { inputUsdPerMTok: 0.75, outputUsdPerMTok: 4.5, cacheReadUsdPerMTok: 0.075 },
  'gpt-5.4': { inputUsdPerMTok: 2.5, outputUsdPerMTok: 15.0, cacheReadUsdPerMTok: 0.25 },
  'gpt-5.5': { inputUsdPerMTok: 5.0, outputUsdPerMTok: 30.0, cacheReadUsdPerMTok: 0.5 },
};

/**
 * Compute dollars from token usage, or null when the model has no price
 * entry or the usage carries no token counts (both non-fatal by design).
 * Cached input tokens are billed at the cache-read rate when priced.
 */
export function costUsd(model: string, usage: PhaseUsage): number | null {
  const entry = PRICES[model];
  if (!entry) {
    return null;
  }
  const input = usage.inputTokens;
  const output = usage.outputTokens;
  const cached = usage.cachedInputTokens;
  if (input === undefined && output === undefined && cached === undefined) {
    return null;
  }
  const cacheRead = entry.cacheReadUsdPerMTok ?? entry.inputUsdPerMTok;
  return (
    ((input ?? 0) * entry.inputUsdPerMTok +
      (output ?? 0) * entry.outputUsdPerMTok +
      (cached ?? 0) * cacheRead) /
    1_000_000
  );
}
