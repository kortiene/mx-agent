/**
 * Runner selection and lazy adapter loading (PLAN.md D3).
 *
 * Each adapter is reached only through a dynamic `import()`, so installing or
 * selecting one runner never requires the other three SDKs (or their native
 * binaries). A missing adapter/SDK surfaces as a typed
 * `RunnerNotInstalledError`, never a raw module-load crash.
 */

import { AdwError, RunnerNotInstalledError } from './errors.js';
import { RUNNER_IDS, type AgentRunner, type RunnerId } from './invoker.js';

/** First runner to ship and the cutover gate (PLAN.md roadmap step 6). */
export const DEFAULT_RUNNER: RunnerId = 'claude';

/** Shape every runner adapter module must export. */
export interface RunnerModule {
  createRunner(): AgentRunner | Promise<AgentRunner>;
}

interface AdapterSpec {
  /** Adapter module specifier, relative to this file (compiled .js name). */
  module: string;
  /** The optionalDependency whose absence makes this runner unavailable. */
  sdkPackage: string;
}

const ADAPTERS: Record<RunnerId, AdapterSpec> = {
  claude: { module: './runners/runner-claude.js', sdkPackage: '@anthropic-ai/claude-agent-sdk' },
  codex: { module: './runners/runner-codex.js', sdkPackage: '@openai/codex-sdk' },
  opencode: { module: './runners/runner-opencode.js', sdkPackage: '@opencode-ai/sdk' },
  pi: { module: './runners/runner-pi.js', sdkPackage: '@earendil-works/pi-coding-agent' },
};

/**
 * Validate a `--runner` / `MX_AGENT_RUNNER` value. Unset/empty falls back to
 * the default; anything unknown throws (mirroring the Python validation at
 * adw/_orchestrator.py:557-559 — fail loud, never guess).
 */
export function resolveRunnerId(raw?: string | null): RunnerId {
  if (raw === undefined || raw === null || raw === '') {
    return DEFAULT_RUNNER;
  }
  if ((RUNNER_IDS as readonly string[]).includes(raw)) {
    return raw as RunnerId;
  }
  throw new AdwError(`unknown runner: '${raw}' (valid: ${RUNNER_IDS.join(', ')})`);
}

/**
 * Dynamically import the adapter for `id` and construct its runner.
 *
 * Module-resolution failures (the adapter not shipped yet, or its optional
 * SDK not installed) become `RunnerNotInstalledError`; errors thrown by the
 * adapter's own code are bugs and propagate unchanged.
 */
export async function loadRunner(id: RunnerId): Promise<AgentRunner> {
  const spec = ADAPTERS[id];
  let mod: Partial<RunnerModule>;
  try {
    mod = (await import(spec.module)) as Partial<RunnerModule>;
  } catch (err) {
    if (isModuleNotFound(err)) {
      throw new RunnerNotInstalledError(id, spec.sdkPackage, { cause: err });
    }
    throw err;
  }
  if (typeof mod.createRunner !== 'function') {
    throw new AdwError(`runner adapter '${spec.module}' does not export createRunner()`);
  }
  const runner = await mod.createRunner();
  if (runner.id !== id) {
    throw new AdwError(`runner adapter mismatch: asked for '${id}', got '${runner.id}'`);
  }
  return runner;
}

/**
 * Recognize "module/package not found" across the loaders we run under:
 * Node ESM (ERR_MODULE_NOT_FOUND), CJS interop (MODULE_NOT_FOUND), and
 * vitest/vite-node's rewritten dynamic imports (message-based). Loaders may
 * wrap the original error, so the `cause` chain is walked too (bounded —
 * causes can cycle).
 */
function isModuleNotFound(err: unknown, depth = 0): boolean {
  if (typeof err !== 'object' || err === null || depth > 4) {
    return false;
  }
  const code = (err as { code?: unknown }).code;
  if (code === 'ERR_MODULE_NOT_FOUND' || code === 'MODULE_NOT_FOUND') {
    return true;
  }
  const message = (err as { message?: unknown }).message;
  if (
    typeof message === 'string' &&
    (message.includes('Cannot find module') ||
      message.includes('Cannot find package') ||
      message.includes('Failed to resolve import') ||
      message.includes('Failed to load url'))
  ) {
    return true;
  }
  return isModuleNotFound((err as { cause?: unknown }).cause, depth + 1);
}
