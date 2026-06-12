import { describe, expect, it, vi } from 'vitest';

// Keep this file hermetic (PLAN.md Section 9: every SDK is mocked, optional
// deps may legitimately be absent): loadRunner('claude'/'codex'/'opencode')
// pulls in the adapter modules, whose static SDK imports must not load the
// real packages.
vi.mock('@anthropic-ai/claude-agent-sdk', () => ({ query: vi.fn() }));
vi.mock('@openai/codex-sdk', () => ({ Codex: vi.fn() }));
vi.mock('@opencode-ai/sdk/v2/client', () => ({ createOpencodeClient: vi.fn() }));

import { AdwError } from '../src/errors.js';
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
  it('loads every shipped adapter (claude: step 6; codex: step 7; opencode: step 8; pi: step 9)', async () => {
    const SHIPPED = {
      claude: 'explicit-no-inherit',
      codex: 'explicit-no-inherit',
      opencode: 'subprocess-allowlist',
      pi: 'subprocess-allowlist',
    } as const;
    expect(Object.keys(SHIPPED).sort()).toEqual([...RUNNER_IDS].sort());
    for (const [id, envIsolation] of Object.entries(SHIPPED)) {
      const runner = await loadRunner(id as keyof typeof SHIPPED);
      expect(runner.id).toBe(id);
      expect(runner.caps.envIsolation).toBe(envIsolation);
      expect(typeof runner.runPhase).toBe('function');
    }
  });

  // The pi adapter drives the CLI's --mode json stream and imports no SDK,
  // so it loads even where the optionalDependency was skipped (its engines
  // floor is node >=22.19): RunnerNotInstalledError can never apply to pi —
  // a missing `pi` BINARY surfaces per-phase as a failed PhaseResult instead.
  // The absent-SDK path for the other runners (the step-3 verify criterion)
  // is covered in registry-not-installed.test.ts, which needs its own file
  // because the SDK mock there must THROW module-not-found at import time.
  it('loads pi without touching any SDK package', async () => {
    const runner = await loadRunner('pi');
    expect(runner.id).toBe('pi');
    expect(runner.caps.nativeSchema).toBe(false);
  });
});
