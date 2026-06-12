/**
 * Scriptable mock runner for orchestrator/parity tests (PLAN.md Section 10:
 * "mock the AgentRunner interface, not the SDK"). Tests script per-call
 * outcomes and inspect the exact PhaseRequests the control plane built —
 * including the env allowlist, which must never carry GH_TOKEN or any
 * MATRIX_-/MX_AGENT_-prefixed key in phased mode.
 */

import type {
  AgentRunner,
  PhaseRequest,
  PhaseResult,
  RunnerCaps,
  RunnerId,
} from '../invoker.js';

export type MockScript = (
  req: PhaseRequest,
  callIndex: number,
) => Partial<PhaseResult> | Promise<Partial<PhaseResult>>;

export interface MockRunnerOptions {
  /** Identity the mock reports; defaults to 'claude'. */
  id?: RunnerId;
  caps?: Partial<RunnerCaps>;
  /** Per-call outcome; defaults to an empty-success result. */
  script?: MockScript;
}

export interface MockRunner extends AgentRunner {
  /** Every request the control plane issued, in order. */
  readonly requests: PhaseRequest[];
  startCalls: number;
  stopCalls: number;
}

/** claude-like defaults: the first runner to ship (PLAN.md Section 5). */
const DEFAULT_CAPS: RunnerCaps = {
  nativeSchema: true,
  perToolHook: true,
  envIsolation: 'explicit-no-inherit',
  costUsd: true,
  nativeBudget: true,
  resume: true,
};

const DEFAULT_RESULT: PhaseResult = {
  ok: true,
  structured: null,
  transcriptText: '',
  usage: {},
  rc: 0,
  signal: 'none',
};

export function createMockRunner(options: MockRunnerOptions = {}): MockRunner {
  const requests: PhaseRequest[] = [];
  const runner: MockRunner = {
    id: options.id ?? 'claude',
    caps: { ...DEFAULT_CAPS, ...options.caps },
    requests,
    startCalls: 0,
    stopCalls: 0,
    async start() {
      runner.startCalls += 1;
    },
    async runPhase(req: PhaseRequest): Promise<PhaseResult> {
      const index = requests.length;
      requests.push(req);
      const partial = options.script ? await options.script(req, index) : {};
      return { ...DEFAULT_RESULT, ...partial };
    },
    async stop() {
      runner.stopCalls += 1;
    },
  };
  return runner;
}
