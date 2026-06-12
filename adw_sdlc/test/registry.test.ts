import { describe, expect, it } from 'vitest';

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
  // No adapter modules exist yet (they land in roadmap steps 6-9), so every
  // id must surface the typed not-installed error — the step-3 verify
  // criterion. When an adapter ships, move its id out of this loop.
  it('surfaces an absent adapter/SDK as RunnerNotInstalledError, not a module-load crash', async () => {
    for (const id of RUNNER_IDS) {
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
