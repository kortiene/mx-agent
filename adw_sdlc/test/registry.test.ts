import { describe, expect, it, vi } from 'vitest';

// Keep this file hermetic (PLAN.md Section 9: every SDK is mocked, optional
// deps may legitimately be absent): loadRunner('claude'/'codex') pulls in the
// adapter modules, whose static SDK imports must not load the real packages.
vi.mock('@anthropic-ai/claude-agent-sdk', () => ({ query: vi.fn() }));
vi.mock('@openai/codex-sdk', () => ({ Codex: vi.fn() }));

import { AdwError, RunnerNotInstalledError } from '../src/errors.js';
import { RUNNER_IDS } from '../src/invoker.js';
import { DEFAULT_RUNNER, loadRunner, resolveRunnerId } from '../src/registry.js';

describe('resolveRunnerId', () => {
  it('accepts each valid id verbatim', () => {
    for (const id of RUNNER_IDS) {
      expect(resolveRunnerId(id)).toBe(id);
    }
  });

  it('falls back to the default runner when unset', () => {
    expect(resolveRunnerId(undefined)).toBe(DEFAULT_RUNNER);
    expect(resolveRunnerId(null)).toBe(DEFAULT_RUNNER);
    expect(resolveRunnerId('')).toBe(DEFAULT_RUNNER);
    expect(RUNNER_IDS).toContain(DEFAULT_RUNNER);
  });

  it('throws a typed error naming the valid ids on unknown values', () => {
    // Mirrors the Python validation (adw/_orchestrator.py): fail loud, never guess.
    for (const bad of ['gpt', 'CLAUDE', 'claude ', 'pi,codex']) {
      let caught: unknown;
      try {
        resolveRunnerId(bad);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(AdwError);
      for (const id of RUNNER_IDS) {
        expect((caught as Error).message).toContain(id);
      }
    }
  });
});

describe('loadRunner', () => {
  it('loads the shipped adapters (claude: step 6; codex: step 7)', async () => {
    for (const id of ['claude', 'codex'] as const) {
      const runner = await loadRunner(id);
      expect(runner.id).toBe(id);
      expect(runner.caps.envIsolation).toBe('explicit-no-inherit');
      expect(typeof runner.runPhase).toBe('function');
    }
  });

  // The remaining adapters land in roadmap steps 8-9; until then their ids
  // must surface the typed not-installed error — the step-3 verify
  // criterion. When an adapter ships, move its id out of this loop.
  it('surfaces an absent adapter/SDK as RunnerNotInstalledError, not a module-load crash', async () => {
    for (const id of RUNNER_IDS.filter((candidate) => candidate !== 'claude' && candidate !== 'codex')) {
      const err: unknown = await loadRunner(id).then(
        () => null,
        (e: unknown) => e,
      );
      expect(err, `loadRunner('${id}')`).toBeInstanceOf(RunnerNotInstalledError);
      const typed = err as RunnerNotInstalledError;
      expect(typed).toBeInstanceOf(AdwError); // catchable as the base type
      expect(typed.runner).toBe(id);
      expect(typed.message).toContain(typed.sdkPackage);
      expect(typed.cause).toBeDefined(); // original loader error preserved for debugging
    }
  });
});
