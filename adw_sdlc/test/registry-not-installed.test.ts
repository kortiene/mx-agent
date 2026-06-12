/**
 * The absent-optional-SDK path of loadRunner (the step-3 verify criterion):
 * a runner whose SDK package is not installed must surface as the typed
 * RunnerNotInstalledError, never a raw module-load crash.
 *
 * All four adapters now ship and CI installs every optional SDK, so genuine
 * absence cannot be reproduced here; instead the codex SDK mock THROWS the
 * Node ESM module-not-found error at import time. vitest wraps a throwing
 * factory in its own error with the original as `cause` — which is exactly
 * the loader-wrapping shape registry.isModuleNotFound must see through (it
 * walks the cause chain). This file is separate from registry.test.ts
 * because vi.mock is file-scoped and that file needs working SDK mocks.
 */

import { describe, expect, it, vi } from 'vitest';

vi.mock('@openai/codex-sdk', () => {
  const err = new Error("Cannot find module '@openai/codex-sdk'") as Error & { code: string };
  err.code = 'ERR_MODULE_NOT_FOUND';
  throw err;
});

import { AdwError, RunnerNotInstalledError } from '../src/errors.js';
import { loadRunner } from '../src/registry.js';

describe('loadRunner with an absent optional SDK', () => {
  it('surfaces RunnerNotInstalledError naming the runner and its package', async () => {
    const err: unknown = await loadRunner('codex').then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(RunnerNotInstalledError);
    const typed = err as RunnerNotInstalledError;
    expect(typed).toBeInstanceOf(AdwError); // catchable as the base type
    expect(typed.runner).toBe('codex');
    expect(typed.message).toContain(typed.sdkPackage);
    expect(typed.cause).toBeDefined(); // original loader error preserved for debugging
  });
});
