/**
 * Price table for TOKEN-ONLY backends (PLAN.md D1 / Section 6).
 *
 * claude, opencode, and pi report dollars natively, so they never consult
 * this table. It exists only for backends that report tokens without cost:
 * the shared Anthropic-SDK classify call today, and codex once its model ids
 * are verified (roadmap step 7 — intentionally absent until then). A missing
 * or stale entry yields a null cost, which is non-fatal: it only disables
 * the parent-side budget gate for that backend.
 */

import type { PhaseUsage } from './invoker.js';

export interface PriceEntry {
  inputUsdPerMTok: number;
  outputUsdPerMTok: number;
  cacheReadUsdPerMTok?: number;
  cacheWrite5mUsdPerMTok?: number;
}

/** Verified against the Claude pricing reference, 2026-06 (haiku: $1/$5, cache read 0.1x, 5m write 1.25x). */
export const PRICES: Record<string, PriceEntry> = {
  'claude-haiku-4-5': {
    inputUsdPerMTok: 1.0,
    outputUsdPerMTok: 5.0,
    cacheReadUsdPerMTok: 0.1,
    cacheWrite5mUsdPerMTok: 1.25,
  },
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
