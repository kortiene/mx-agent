/**
 * The single runner seam (PLAN.md D6, Section 3.2).
 *
 * The orchestrator calls `AgentRunner.runPhase()` exactly once per agentic
 * phase; everything runner-specific hides behind this interface plus the
 * `RunnerCaps` capability matrix. The control plane branches only on caps,
 * never on runner identity. The nudge-retry and no-retry-on-timeout logic
 * will live once in the invoker layer over `runPhase` (roadmap step 5), so
 * adapters return raw outcomes and never retry themselves.
 */

/** The four interchangeable runner backends behind the AgentRunner interface (PLAN.md D1). */
export const RUNNER_IDS = ['claude', 'codex', 'opencode', 'pi'] as const;

export type RunnerId = (typeof RUNNER_IDS)[number];

/** A JSON Schema document (produced from Zod via `z.toJSONSchema()`). */
export type JsonSchema = Record<string, unknown>;

/**
 * Abort-reason message the invoker uses when the per-phase timer fires.
 * Adapters classify an abort whose reason mentions "timeout" as
 * `PhaseResult.signal:'timeout'` (vs 'cancelled'); producer, adapters, and
 * tests all reference this constant so the contract cannot drift silently.
 */
export const PHASE_TIMEOUT_ABORT_REASON = 'phase timeout';

/** Tier→effort hint; a runner maps it to its native knob or ignores it. */
export type ReasoningEffort = 'minimal' | 'low' | 'medium' | 'high';

export interface PhaseRequest {
  /** plan|implement|tests|resolve|e2e|review|patch|document (classify never reaches runPhase). */
  phase: string;
  /** Composed prompt (preamble + context + body + footer), built by the control plane. */
  prompt: string;
  /** Resolved tier→modelId for THIS runner (per-runner registry in models.ts). */
  model: string;
  reasoning?: ReasoningEffort;
  /** The worktree the agent reads and edits. */
  cwd: string;
  /**
   * EXPLICIT allowlist built by safeSubprocessEnv(); the ONLY env the backend
   * may hand its child. Adapters must never merge process.env on top (D5).
   */
  env: Record<string, string>;
  /** Per-phase JSON Schema for structured output; absent ⇒ free-form. */
  schema?: JsonSchema;
  /** Forwarded to backends with native budget gating (claude maxBudgetUsd). */
  maxBudgetUsd?: number;
  /** agents/{adw_id}/{phase}/transcript.log — adapters tee output here during the run. */
  transcriptPath: string;
  /** Orchestrator-owned timeout/cancel; adapters must observe it and report via PhaseResult.signal. */
  signal: AbortSignal;
}

/** Native usage where the backend reports it; the parent fills cost for token-only backends. */
export interface PhaseUsage {
  inputTokens?: number;
  outputTokens?: number;
  cachedInputTokens?: number;
  reasoningTokens?: number;
  /** Dollars when known (native or parent-computed); null when unpriceable (non-fatal). */
  costUsd?: number | null;
}

export interface PhaseResult {
  ok: boolean;
  /** Normalized structured payload; the parent always re-validates with Zod (defense in depth). */
  structured: Record<string, unknown> | null;
  /** Full transcript text (also teed to PhaseRequest.transcriptPath during the run). */
  transcriptText: string;
  usage: PhaseUsage;
  /** 0 ok; nonzero failures feed the bounded loops exactly as a failed CLI run does today. */
  rc: number;
  /** Drives no-retry-on-timeout; 'budget' = a native cost cap fired (fail fast, no nudge). */
  signal: 'none' | 'timeout' | 'cancelled' | 'budget';
  /** For resume where the backend supports it (claude session, codex thread, opencode session, pi session). */
  sessionId?: string;
}

/**
 * Capability matrix (PLAN.md Section 5). A runner that cannot satisfy a
 * parity line is documented here, not silently broken; the control plane
 * branches on these flags only.
 */
export interface RunnerCaps {
  /** Backend constrains output to a JSON schema natively (claude/codex/opencode-v2; pi = false). */
  nativeSchema: boolean;
  /** Programmatic per-tool veto (claude canUseTool only; codex = sandbox-coarse; opencode/pi = event). */
  perToolHook: boolean;
  /**
   * 'explicit-no-inherit': the SDK passes our env object verbatim to its own
   * child (claude options.env, codex CodexOptions.env). 'subprocess-allowlist':
   * the orchestrator owns the spawn and its env (opencode serve, pi).
   */
  envIsolation: 'explicit-no-inherit' | 'subprocess-allowlist';
  /** Backend reports dollars natively (claude/opencode/pi; codex is token-only → pricing.ts). */
  costUsd: boolean;
  /** Backend enforces maxBudgetUsd itself (claude only). */
  nativeBudget: boolean;
  /** sessionId resume supported. */
  resume: boolean;
}

export interface AgentRunner {
  readonly id: RunnerId;
  readonly caps: RunnerCaps;
  /** opencode spawns/awaits its server here; in-process backends omit or no-op. */
  start?(): Promise<void>;
  runPhase(req: PhaseRequest): Promise<PhaseResult>;
  /** opencode kills its server here; in-process backends omit or no-op. */
  stop?(): Promise<void>;
}
