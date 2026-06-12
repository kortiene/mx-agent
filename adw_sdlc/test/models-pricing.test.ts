import { describe, expect, it } from 'vitest';

import { RUNNER_IDS } from '../src/invoker.js';
import { CLASSIFY_MODEL, PHASE_TIER, TIER_MODELS, modelForPhase } from '../src/models.js';
import { PRICES, costUsd } from '../src/pricing.js';

describe('modelForPhase', () => {
  it('resolves tier defaults per runner (adw/_phases.py parity)', () => {
    expect(modelForPhase('classify', 'claude', { env: {} })).toBe('claude-haiku-4-5');
    expect(modelForPhase('implement', 'claude', { env: {} })).toBe('claude-opus-4-8');
    expect(modelForPhase('tests', 'claude', { env: {} })).toBe('claude-sonnet-4-6');
    expect(modelForPhase('implement', 'pi', { env: {} })).toBe('opus'); // bare names, Python TIER_MODELS verbatim
  });

  it('honors precedence: --model > MX_AGENT_MODEL_<PHASE> > tier', () => {
    const env = { MX_AGENT_MODEL_IMPLEMENT: 'env-model' };
    expect(modelForPhase('implement', 'claude', { cliModel: 'cli-model', env })).toBe('cli-model');
    expect(modelForPhase('implement', 'claude', { env })).toBe('env-model');
    expect(modelForPhase('review', 'claude', { env })).toBe('claude-opus-4-8'); // override is per-phase
  });

  it('unknown phases fall back to the mid tier', () => {
    expect(modelForPhase('mystery', 'claude', { env: {} })).toBe('claude-sonnet-4-6');
  });

  it('every runner has a complete tier map and classify stays on haiku', () => {
    for (const runner of RUNNER_IDS) {
      for (const tier of ['cheap', 'mid', 'capable'] as const) {
        expect(TIER_MODELS[runner][tier], `${runner}/${tier}`).toBeTruthy();
      }
    }
    expect(CLASSIFY_MODEL).toBe('claude-haiku-4-5');
    expect(new Set(Object.values(PHASE_TIER))).toEqual(new Set(['cheap', 'mid', 'capable']));
  });
});

describe('costUsd', () => {
  it('prices the classify model from the table', () => {
    // 100k input + 10k output + 50k cache-read on haiku ($1/$5/$0.1 per MTok)
    const cost = costUsd('claude-haiku-4-5', {
      inputTokens: 100_000,
      outputTokens: 10_000,
      cachedInputTokens: 50_000,
    });
    expect(cost).toBeCloseTo(0.1 + 0.05 + 0.005, 10);
  });

  it('prices the codex tiers from the table (verified in step 7)', () => {
    // 100k input + 10k output + 50k cache-read on gpt-5.5 ($5/$30/$0.5 per MTok)
    const cost = costUsd('gpt-5.5', {
      inputTokens: 100_000,
      outputTokens: 10_000,
      cachedInputTokens: 50_000,
    });
    expect(cost).toBeCloseTo(0.5 + 0.3 + 0.025, 10);
  });

  it('returns null for unpriced models and empty usage (non-fatal by design)', () => {
    expect(costUsd('gpt-99-experimental', { inputTokens: 1000 })).toBeNull();
    expect(costUsd('claude-haiku-4-5', {})).toBeNull();
  });

  it('table stays scoped to token-only backends', () => {
    // claude/opencode/pi report cost natively; only the anthropic classify
    // model and the codex tiers (token-only, step 7) belong here.
    expect(Object.keys(PRICES).sort()).toEqual(
      ['claude-haiku-4-5', ...Object.values(TIER_MODELS.codex)].sort(),
    );
  });
});
