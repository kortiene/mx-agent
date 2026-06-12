/**
 * adw_sdlc — TypeScript control plane for the phased ADW pipeline.
 *
 * Landed so far (PLAN.md roadmap): the AgentRunner seam + capability matrix
 * (invoker.ts), typed errors, and the lazy runner registry (registry.ts).
 * The orchestrator, phases, env allowlist, and the four adapters land in
 * later steps.
 */

/** Engine identity recorded additively in state.json once runs are driven from TS. */
export const ENGINE = 'ts' as const;

export {
  RUNNER_IDS,
  type AgentRunner,
  type JsonSchema,
  type PhaseRequest,
  type PhaseResult,
  type PhaseUsage,
  type ReasoningEffort,
  type RunnerCaps,
  type RunnerId,
} from './invoker.js';
export { AdwError, RunnerNotInstalledError } from './errors.js';
export { DEFAULT_RUNNER, loadRunner, resolveRunnerId, type RunnerModule } from './registry.js';
export {
  ISSUE_CLASSES,
  PHASE_SCHEMAS,
  parsePhaseResult,
  phaseJsonSchema,
  type ClassifyResult,
  type DocumentResult,
  type E2EResult,
  type ImplementResult,
  type PatchResult,
  type PlanResult,
  type ResolveResult,
  type ReviewFinding,
  type ReviewResult,
  type SchemaPhase,
  type TestsResult,
} from './schemas.js';
export { CLASSIFY_MODEL, PHASE_TIER, TIER_MODELS, modelForPhase, type ModelOverrides, type Tier } from './models.js';
export { PRICES, costUsd, type PriceEntry } from './pricing.js';
