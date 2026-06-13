/**
 * The invoker layer over AgentRunner.runPhase (PLAN.md D6 / Section 7):
 * compose the prompt, persist prompt.txt, drive exactly one runner call —
 * with the single nudge-retry and the no-retry-on-timeout mapping living
 * HERE, once, never per adapter — and return the Zod-validated phase result.
 *
 * Semantics carried from adw/_phases.py:482-517 run_agent_phase:
 * - the reply is parsed regardless of exit code; a nonzero rc with parseable
 *   output is still a success (the bounded loops act on the parsed counts);
 * - a timed-out/killed runner won't do better on a re-run with the same time
 *   box, so a timeout (or a native budget/cancel signal) fails fast with NO
 *   nudge — only a parse/validation failure on a clean run earns the single
 *   nudge retry;
 * - a native-schema backend returning a non-conforming or null payload
 *   triggers the same single nudge (PLAN.md Section 7).
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { parseJson, REPO_ROOT } from './common.js';
import { AdwError } from './errors.js';
import { PHASE_TIMEOUT_ABORT_REASON } from './invoker.js';
import type { AgentRunner, PhaseResult, PhaseUsage } from './invoker.js';
import { modelForPhase } from './models.js';
import { composePhasePrompt, type AgentPhase } from './phases.js';
import { parsePhaseResult, phaseJsonSchema, PHASE_SCHEMAS, type SchemaPhase } from './schemas.js';
import type { AdwState } from './state.js';
import type { z } from 'zod';

/** Verbatim from adw/_phases.py:472. */
export const NUDGE =
  '\n\nRespond with ONLY the required JSON object in a ```json fenced block, nothing else.';

export interface RunAgentPhaseOptions {
  phase: SchemaPhase;
  templateArgs: readonly string[];
  state: AdwState;
  runner: AgentRunner;
  /** --model override; per-phase MX_AGENT_MODEL_<PHASE> still applies under it. */
  cliModel?: string;
  /** The allowlist env the orchestrator built (safeSubprocessEnv). */
  env: Record<string, string>;
  /** The worktree the agent edits; defaults to the repo root. */
  cwd?: string;
  /** Per-call timeout in milliseconds; 0/undefined = none. */
  timeoutMs?: number;
  /** Forwarded to backends with native budget gating (claude). */
  maxBudgetUsd?: number;
}

export interface AgentPhaseOutcome<P extends SchemaPhase = SchemaPhase> {
  data: z.infer<(typeof PHASE_SCHEMAS)[P]>;
  usage: PhaseUsage;
  sessionId?: string;
}

/**
 * Render+run one agent phase through the runner seam and return its
 * validated result. Retries once with a "respond with JSON only" nudge if
 * the first reply does not parse/validate; a second failure (or any
 * timeout/budget/cancel signal) raises AdwError.
 */
export async function runAgentPhase<P extends SchemaPhase>(
  options: RunAgentPhaseOptions & { phase: P },
): Promise<AgentPhaseOutcome<P>> {
  const { phase, state, runner } = options;
  const emitJsonContract = !runner.caps.nativeSchema;
  const prompt = composePhasePrompt(
    phase as AgentPhase,
    options.templateArgs,
    state,
    runner.id,
    emitJsonContract,
  );
  const phaseDir = state.phaseDir(phase);
  writeFileSync(join(phaseDir, 'prompt.txt'), prompt, 'utf8');
  const model = modelForPhase(phase, runner.id, { cliModel: options.cliModel ?? '' });
  const schema = runner.caps.nativeSchema ? phaseJsonSchema(phase) : undefined;

  const invoke = async (text: string, transcriptName: string): Promise<PhaseResult> => {
    const controller = new AbortController();
    const timeoutMs = options.timeoutMs ?? 0;
    const timer =
      timeoutMs > 0
        ? setTimeout(() => controller.abort(new Error(PHASE_TIMEOUT_ABORT_REASON)), timeoutMs)
        : null;
    try {
      const request = {
        phase,
        prompt: text,
        model,
        cwd: options.cwd ?? REPO_ROOT,
        env: options.env,
        transcriptPath: join(phaseDir, transcriptName),
        signal: controller.signal,
        ...(schema !== undefined ? { schema } : {}),
        ...(options.maxBudgetUsd !== undefined ? { maxBudgetUsd: options.maxBudgetUsd } : {}),
      };
      return await runner.runPhase(request);
    } finally {
      if (timer !== null) {
        clearTimeout(timer);
      }
    }
  };

  const extract = (result: PhaseResult): z.infer<(typeof PHASE_SCHEMAS)[P]> => {
    const payload = result.structured ?? parseJson(result.transcriptText, 'object');
    return parsePhaseResult(phase, payload);
  };

  const first = await invoke(prompt, 'transcript.log');
  try {
    return { data: extract(first), usage: first.usage, ...sessionOf(first) };
  } catch (err) {
    if (!(err instanceof AdwError)) {
      throw err;
    }
    // Mirrors the _TIMEOUT_EXIT_CODES fail-fast: a run the parent had to kill
    // (or that hit a native cost cap) gets no nudge.
    if (first.signal === 'timeout') {
      throw new AdwError(`${phase} phase runner timed out without parseable output`, { cause: err });
    }
    if (first.signal === 'budget') {
      throw new AdwError(`${phase} phase hit the native budget cap without parseable output`, {
        cause: err,
      });
    }
    if (first.signal === 'cancelled') {
      throw new AdwError(`${phase} phase was cancelled without parseable output`, { cause: err });
    }
    // Native-schema backends get the retry WITH the fenced-JSON contract:
    // their first prompt deliberately omits it (the schema rides the native
    // channel), but the SDK can return success without a conforming payload
    // (structured_output is optional on SDKResultSuccess) — and a bare NUDGE
    // would demand "the required JSON object" the agent was never shown.
    const retryPrompt = emitJsonContract
      ? prompt
      : composePhasePrompt(phase as AgentPhase, options.templateArgs, state, runner.id, true);
    const second = await invoke(retryPrompt + NUDGE, 'transcript-2.log');
    // Both attempts consumed tokens; report the pair's combined usage.
    return { data: extract(second), usage: mergeUsage(first.usage, second.usage), ...sessionOf(second) };
  }
}

function sessionOf(result: PhaseResult): { sessionId?: string } {
  return result.sessionId !== undefined ? { sessionId: result.sessionId } : {};
}

function addCounts(a: number | undefined, b: number | undefined): number | undefined {
  return a === undefined && b === undefined ? undefined : (a ?? 0) + (b ?? 0);
}

function mergeUsage(a: PhaseUsage, b: PhaseUsage): PhaseUsage {
  const usage: PhaseUsage = {};
  const inputTokens = addCounts(a.inputTokens, b.inputTokens);
  const outputTokens = addCounts(a.outputTokens, b.outputTokens);
  const cachedInputTokens = addCounts(a.cachedInputTokens, b.cachedInputTokens);
  const reasoningTokens = addCounts(a.reasoningTokens, b.reasoningTokens);
  if (inputTokens !== undefined) usage.inputTokens = inputTokens;
  if (outputTokens !== undefined) usage.outputTokens = outputTokens;
  if (cachedInputTokens !== undefined) usage.cachedInputTokens = cachedInputTokens;
  if (reasoningTokens !== undefined) usage.reasoningTokens = reasoningTokens;
  // null means "could not be priced" (PLAN.md Section 6) — if either attempt
  // is unpriceable the pair's cost is unknown, never a false partial sum.
  if (a.costUsd === null || b.costUsd === null) {
    usage.costUsd = null;
  } else if (a.costUsd !== undefined || b.costUsd !== undefined) {
    usage.costUsd = (a.costUsd ?? 0) + (b.costUsd ?? 0);
  }
  return usage;
}
