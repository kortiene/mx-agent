/**
 * Engine parity under the ts engine (PLAN.md roadmap step 10 Verify): the
 * orchestrator chain runs identically for each shipped runner, producing
 * equivalent state.json documents that validate against the cross-language
 * contract (adw/state.schema.json).
 *
 * Two layers, per Section 10's "mock the AgentRunner interface, not the SDK":
 * 1. Each runner's IDENTITY + real capability profile (its exported CAPS)
 *    through a scripted mock runner and the REAL invoker layer — so the
 *    nativeSchema split (structured payload vs fenced-JSON transcript, pi)
 *    exercises both extraction paths end to end.
 * 2. The real claude adapter (the cutover-gate runner) over a vi-mocked SDK,
 *    bound through the actual CLI ts-engine path (real registry.loadRunner),
 *    asserting the wiring main() → loadRunner → orchestrator.run with no
 *    seam substituted except the SDK itself and the git/gh effects.
 * Per-adapter transport fidelity for codex/opencode/pi stays where it is
 * already proven: their own SDK-/spawn-mocked suites (steps 7-9).
 */

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@anthropic-ai/claude-agent-sdk', () => ({ query: vi.fn() }));
vi.mock('@openai/codex-sdk', () => ({ Codex: class {} }));
vi.mock('@opencode-ai/sdk/v2/client', () => ({ createOpencodeClient: vi.fn() }));

import { query } from '@anthropic-ai/claude-agent-sdk';

import { main } from '../src/cli.js';
import { REPO_ROOT } from '../src/common.js';
import type { AgentRunner, PhaseRequest, RunnerId } from '../src/invoker.js';
import { run, type OrchestratorDeps } from '../src/orchestrator.js';
import { loadRunner } from '../src/registry.js';
import { CLAUDE_CAPS } from '../src/runners/runner-claude.js';
import { CODEX_CAPS } from '../src/runners/runner-codex.js';
import { createMockRunner } from '../src/runners/runner-mock.js';
import { OPENCODE_CAPS } from '../src/runners/runner-opencode.js';
import { PI_CAPS } from '../src/runners/runner-pi.js';
import { AdwState, setAgentsDir } from '../src/state.js';
import { validate, type Schema } from './helpers/state-schema.js';

const queryMock = vi.mocked(query);

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'adw-parity-'));
  setAgentsDir(tmp);
  queryMock.mockReset();
});

afterEach(() => {
  setAgentsDir(null);
  rmSync(tmp, { recursive: true, force: true });
});

const RUNNER_CAPS = {
  claude: CLAUDE_CAPS,
  codex: CODEX_CAPS,
  opencode: OPENCODE_CAPS,
  pi: PI_CAPS,
} as const;

/** Same canned per-phase results as the run() integration suite. */
const PHASE_RESULTS: Record<string, Record<string, unknown>> = {
  plan: { plan_file: 'specs/x.md', spec_created: true, summary: '' },
  implement: { summary: 'did it', files_changed: ['src/lib.rs'] },
  tests: { tests_added: true, summary: '' },
  review: { findings: [], wrote_commit_message: true, wrote_pr_body: true },
};

const COMMIT_MESSAGE = 'feat: phased pipeline\n\ncloses #5';
const PR_BODY = 'Closes #5\n\nImplements the thing.';

/** agents/{id}/{phase}/transcript.log -> agents/{id} (the run workspace). */
function workspaceOf(req: PhaseRequest): string {
  return dirname(dirname(req.transcriptPath));
}

function writeArtifacts(workspace: string): void {
  mkdirSync(workspace, { recursive: true });
  writeFileSync(join(workspace, 'commit_message.txt'), COMMIT_MESSAGE, 'utf8');
  writeFileSync(join(workspace, 'pr_body.md'), PR_BODY, 'utf8');
}

/**
 * Scripted runner wearing a real runner's identity + caps. nativeSchema
 * backends reply with a structured payload; pi (nativeSchema:false) replies
 * with the trailing-fenced-JSON transcript its CLI stream produces, driving
 * the invoker's parse path instead.
 */
function profiledRunner(id: RunnerId): AgentRunner {
  const caps = RUNNER_CAPS[id];
  return createMockRunner({
    id,
    caps,
    script: (req) => {
      const payload = PHASE_RESULTS[req.phase];
      if (payload === undefined) {
        throw new Error(`unexpected phase: ${req.phase}`);
      }
      if (req.phase === 'review') {
        writeArtifacts(workspaceOf(req));
      }
      const usage = { inputTokens: 100, outputTokens: 50, costUsd: 0.02 };
      if (caps.nativeSchema) {
        expect(req.schema).toBeDefined();
        return { structured: payload, usage };
      }
      expect(req.schema).toBeUndefined();
      expect(req.prompt).toContain('fenced');
      return {
        structured: null,
        transcriptText: `Working on it.\n\n\`\`\`json\n${JSON.stringify(payload)}\n\`\`\`\n`,
        usage,
      };
    },
  });
}

const POISONED_ENV = {
  PATH: '/bin',
  HOME: '/home/u',
  GH_TOKEN: 'ghp_secret',
  MATRIX_TOKEN: 'x',
  MX_AGENT_FOO: 'x',
};

/**
 * External effects stubbed; runAgentPhase is deliberately NOT overridden, so
 * run() falls back to the REAL invoker layer (composePhasePrompt + parse +
 * nudge semantics) — the point of this suite.
 */
function depsWithRealInvoker(): Partial<OrchestratorDeps> {
  const noop = () => {};
  return {
    env: { ...POISONED_ENV },
    isatty: () => false,
    confirm: async () => false,
    sleep: async () => {},
    runCmd: () => ({ rc: 0, output: '' }),
    capture: () => ({ returncode: 0, stdout: '', stderr: '' }),
    workingTreeDirty: () => false,
    changedFiles: () => ['src/lib.rs'],
    resolveGhBin: () => '/bin/gh',
    detectRepo: () => 'o/r',
    issueState: vi.fn().mockReturnValueOnce('OPEN').mockReturnValue('CLOSED'),
    postProgress: noop,
    fetchIssue: () => ({ title: 'T', body: 'B', labels: ['type:feature'] }),
    setStatus: noop,
    git: {
      createOrCheckoutBranch: () => ({ ok: true, error: null }),
      commitAll: () => ({ ok: true, error: null }),
      push: () => ({ ok: true, error: null }),
      pullRebase: () => ({ ok: true, error: null }),
      prForBranch: () => null,
      createPr: () => ({ number: 42, url: 'https://x/pull/42', error: null }),
      ciStatus: () => ({ state: 'success', failingJobs: [] }),
      squashMerge: () => ({ ok: true, error: null }),
    },
    classify: async () => ({ value: { issue_class: 'feat' as const, reason: 'r' }, usage: { costUsd: 0.01 } }),
  };
}

function loadStateDoc(adwId: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(tmp, adwId, 'state.json'), 'utf8')) as Record<string, unknown>;
}

/**
 * Strip the fields that legitimately differ between runs of different
 * runners: the run id, the runner identity, and the branch name (which
 * embeds the run id — asserted per run instead).
 */
function normalized(doc: Record<string, unknown>): Record<string, unknown> {
  const { adw_id: _id, runner: _runner, branch_name: _branch, ...rest } = doc;
  return rest;
}

const SCHEMA = JSON.parse(readFileSync(join(REPO_ROOT, 'adw', 'state.schema.json'), 'utf8')) as Schema;

const RUNS: ReadonlyArray<[RunnerId, string]> = [
  ['claude', 'aaaaaa01'],
  ['codex', 'bbbbbb02'],
  ['opencode', 'cccccc03'],
  ['pi', 'dddddd04'],
];

describe('ts-engine parity across the four shipped runner profiles', () => {
  it('runs the full chain identically and writes equivalent, schema-valid state.json', async () => {
    const docs: Array<[RunnerId, Record<string, unknown>]> = [];

    for (const [id, adwId] of RUNS) {
      const runner = profiledRunner(id);
      const rc = await run(5, runner, { adwId, yes: true, noProgress: true }, depsWithRealInvoker());
      expect(rc, `runner ${id}`).toBe(0);

      const doc = loadStateDoc(adwId);
      expect(validate(doc, SCHEMA), `runner ${id} schema`).toEqual([]);
      expect(doc['engine'], `runner ${id}`).toBe('ts');
      expect(doc['runner']).toBe(id);
      expect(doc['branch_name']).toBe(`feat/5-${adwId}-t`);
      expect(doc['commit_message']).toBe(COMMIT_MESSAGE);
      docs.push([id, doc]);

      // The run is also loadable through the state reader (resume contract).
      const reloaded = AdwState.load(adwId);
      expect(reloaded?.completedPhases).toContain('merge');
    }

    // Equivalence: modulo adw_id + runner identity, the four runs agree on
    // every field — phases, branch, artifacts, findings, costs.
    const [, first] = docs[0]!;
    for (const [id, doc] of docs.slice(1)) {
      expect(normalized(doc), `runner ${id} vs claude`).toEqual(normalized(first));
    }
  });
});

describe('ts engine end-to-end with the REAL claude adapter (mocked SDK)', () => {
  function successResult(structured: Record<string, unknown>): unknown {
    return {
      type: 'result',
      subtype: 'success',
      duration_ms: 5,
      duration_api_ms: 4,
      is_error: false,
      num_turns: 1,
      result: 'done',
      stop_reason: null,
      total_cost_usd: 0.42,
      usage: {
        input_tokens: 100,
        output_tokens: 50,
        cache_read_input_tokens: 10,
        cache_creation_input_tokens: 5,
      },
      modelUsage: {},
      permission_denials: [],
      uuid: 'u-1',
      session_id: 'sess-1',
      structured_output: structured,
    };
  }

  it('main() binds the registry-loaded adapter into run() and completes the chain', async () => {
    const adwId = 'eeeeee05';
    const phaseQueue = ['plan', 'implement', 'tests', 'review'];
    const seenEnvs: Array<Record<string, string | undefined> | undefined> = [];

    queryMock.mockImplementation((args) => {
      seenEnvs.push(args.options?.env);
      const phase = phaseQueue.shift();
      if (phase === undefined) {
        throw new Error('query called more often than the expected 4 agent phases');
      }
      if (phase === 'review') {
        writeArtifacts(join(tmp, adwId));
      }
      return (async function* () {
        yield successResult(PHASE_RESULTS[phase]!) as never;
      })() as never;
    });

    const rc = await main(
      ['5', '--adw-id', adwId, '--yes', '--no-progress'],
      {
        env: { ...POISONED_ENV, MX_AGENT_ENGINE: 'ts', MX_AGENT_RUNNER: 'claude' },
        loadRunner, // the REAL registry: dynamic-imports runner-claude.js
        runIssue: (issue, runner, options) => {
          // The wiring under test hands the registry-loaded adapter through.
          expect(runner.id).toBe('claude');
          expect(runner.caps).toEqual(CLAUDE_CAPS);
          return run(issue, runner, options, depsWithRealInvoker());
        },
      },
    );

    expect(rc).toBe(0);
    expect(phaseQueue).toEqual([]); // all four agent phases ran through the SDK seam
    // D5 spot check at the outermost boundary: the env the SDK would hand its
    // child carries no parent secret, on every call.
    for (const env of seenEnvs) {
      expect(env).toBeDefined();
      expect(env).not.toHaveProperty('GH_TOKEN');
      expect(Object.keys(env!).some((k) => k.startsWith('MATRIX_') || k.startsWith('MX_AGENT_'))).toBe(false);
    }

    const doc = loadStateDoc(adwId);
    expect(validate(doc, SCHEMA)).toEqual([]);
    expect(doc['engine']).toBe('ts');
    expect(doc['runner']).toBe('claude');
    expect(doc['commit_message']).toBe(COMMIT_MESSAGE);
    expect(doc['completed_phases']).toContain('merge');
  });
});
