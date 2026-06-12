/**
 * adw_sdlc — TypeScript control plane for the phased ADW pipeline.
 *
 * Landed so far (PLAN.md roadmap): the AgentRunner seam + capability matrix
 * (invoker.ts), typed errors, the lazy runner registry (registry.ts), and the
 * full control plane (orchestrator/state/git/env/phases) with the shared
 * structured-call classify helper, driven through runner-mock.ts in tests.
 * The four real runner adapters land in roadmap steps 6-9.
 */

/** Engine identity recorded additively in state.json once runs are driven from TS. */
export const ENGINE = 'ts' as const;

export {
  DEFAULT_ENGINE,
  ENGINE_IDS,
  extractEngineFlag,
  main as cliMain,
  parseCliArgs,
  resolveEngineId,
  splitPassthru,
  type CliDeps,
  type EngineId,
  type ParsedCli,
} from './cli.js';

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
export { REPO_ROOT, parseJson, renderPromptFile, shellSplit, stripFrontmatter, substituteArgs } from './common.js';
export {
  BASE_ENV_ALLOW,
  ENV_DENY_PREFIXES,
  RUNNER_ENV_ALLOW,
  safeSubprocessEnv,
  type SafeEnvOptions,
} from './env.js';
export {
  AdwState,
  STATE_FILENAME,
  agentsDir,
  makeAdwId,
  setAgentsDir,
  validateAdwId,
  type AdwStateInit,
  type FindingRecord,
} from './state.js';
export {
  AGENT_PHASES,
  ARTIFACT_PHASES,
  CONDITIONAL_PHASES,
  DEFAULT_PHASES,
  LOOP_PHASES,
  OUTPUT_CONTRACT,
  PHASE_CONTEXT,
  PHASE_PREAMBLE_SHARED,
  TEMPLATE,
  buildFooter,
  commitMessagePath,
  composePhasePrompt,
  gateConditional,
  gateDocument,
  gateE2e,
  parsePhases,
  prBodyPath,
  templatePath,
  type AgentPhase,
  type GateDecision,
} from './phases.js';
export { NUDGE, runAgentPhase, type AgentPhaseOutcome, type RunAgentPhaseOptions } from './run-phase.js';
export {
  structuredCall,
  type AnthropicLike,
  type StructuredCallOptions,
  type StructuredCallResult,
} from './structured-call.js';
export {
  DEFAULT_FINALIZE_GATES,
  DEFAULT_TEST_CMD,
  MAX_OUTPUT_CHARS,
  absorbAuthoredText,
  changedFiles,
  ciFixLoop,
  confirmMerge,
  defaultDeps,
  finalizeGates,
  patchLoop,
  renderFindings,
  resolveLoop,
  run,
  truncate,
  type GitOps,
  type OrchestratorDeps,
  type ProgressFn,
  type RunCmdResult,
  type RunOptions,
} from './orchestrator.js';
export { createMockRunner, type MockRunner, type MockRunnerOptions, type MockScript } from './runners/runner-mock.js';
