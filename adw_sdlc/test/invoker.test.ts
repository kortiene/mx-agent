import { describe, expect, it } from 'vitest';

import type { AgentRunner, PhaseRequest, PhaseResult } from '../src/invoker.js';

// A minimal in-memory runner. Its main job is the compile-time assertion that
// the seam is implementable without optional members or runner-specific
// leakage; the runtime checks below are a smoke test of the result contract.
function makeStubRunner(): AgentRunner {
  return {
    id: 'claude',
    caps: {
      nativeSchema: true,
      perToolHook: true,
      envIsolation: 'explicit-no-inherit',
      costUsd: true,
      nativeBudget: true,
      resume: true,
    },
    async runPhase(req: PhaseRequest): Promise<PhaseResult> {
      return {
        ok: !req.signal.aborted,
        structured: req.schema ? {} : null,
        transcriptText: '',
        usage: { inputTokens: 0, outputTokens: 0, costUsd: null },
        rc: req.signal.aborted ? 1 : 0,
        signal: req.signal.aborted ? 'cancelled' : 'none',
      };
    },
  };
}

function makeRequest(overrides: Partial<PhaseRequest> = {}): PhaseRequest {
  return {
    phase: 'implement',
    prompt: 'do the thing',
    model: 'claude-opus-4-8',
    cwd: '/tmp/worktree',
    env: { PATH: '/usr/bin' },
    transcriptPath: '/tmp/transcript.log',
    signal: new AbortController().signal,
    ...overrides,
  };
}

describe('AgentRunner seam', () => {
  it('start/stop are optional for in-process backends', async () => {
    const runner = makeStubRunner();
    expect(runner.start).toBeUndefined();
    expect(runner.stop).toBeUndefined();
    await runner.start?.();
    await runner.stop?.(); // optional-call pattern the orchestrator will use
  });

  it('runPhase honors an already-aborted signal via PhaseResult.signal', async () => {
    const runner = makeStubRunner();
    const controller = new AbortController();
    controller.abort();
    const result = await runner.runPhase(makeRequest({ signal: controller.signal }));
    expect(result.ok).toBe(false);
    expect(result.signal).toBe('cancelled');
    expect(result.rc).not.toBe(0);
  });

  it('structured output follows the schema presence in the request', async () => {
    const runner = makeStubRunner();
    const withSchema = await runner.runPhase(makeRequest({ schema: { type: 'object' } }));
    expect(withSchema.structured).not.toBeNull();
    const freeForm = await runner.runPhase(makeRequest());
    expect(freeForm.structured).toBeNull();
  });
});
