/**
 * Unit tests for the claude runner adapter (PLAN.md roadmap step 6).
 *
 * The SDK is replaced by vi.mock per the hermetic CI rule (PLAN.md Section 9):
 * no network, no keys, no child processes. The highest-severity case is the
 * env-isolation test — with a poisoned parent env, the options.env object the
 * adapter hands query() (which the SDK passes to its child as the ENTIRE
 * environment, replace semantics) must be exactly the allowlist.
 */

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@anthropic-ai/claude-agent-sdk', () => ({ query: vi.fn() }));

import { query } from '@anthropic-ai/claude-agent-sdk';
import type { Options } from '@anthropic-ai/claude-agent-sdk';

import { safeSubprocessEnv } from '../src/env.js';
import type { AgentRunner, PhaseRequest } from '../src/invoker.js';
import {
  CLAUDE_CAPS,
  CLAUDE_EDIT_TOOLS,
  createRunner,
  denyGitGh,
  resolveClaudeBin,
} from '../src/runners/runner-claude.js';

const queryMock = vi.mocked(query);

let tmp: string;
let runner: AgentRunner;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'adw-runner-claude-'));
  mkdirSync(join(tmp, 'bin'));
  mkdirSync(join(tmp, 'home'));
  runner = createRunner();
  queryMock.mockReset();
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function makeReq(over: Partial<PhaseRequest> = {}): PhaseRequest {
  return {
    phase: 'plan',
    prompt: 'plan the work',
    model: 'claude-opus-4-8',
    cwd: join(tmp, 'worktree'),
    // Empty PATH dir + empty HOME so binary resolution is hermetic per test.
    env: { PATH: join(tmp, 'bin'), HOME: join(tmp, 'home') },
    transcriptPath: join(tmp, 'transcript.log'),
    signal: new AbortController().signal,
    ...over,
  };
}

function assistantMsg(text: string): unknown {
  return {
    type: 'assistant',
    message: { content: [{ type: 'text', text }] },
    parent_tool_use_id: null,
    uuid: 'a-1',
    session_id: 'sess-1',
  };
}

function successResult(over: Record<string, unknown> = {}): unknown {
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
    ...over,
  };
}

function errorResult(subtype: string): unknown {
  return successResult({ subtype, is_error: true, errors: ['boom'], result: undefined });
}

function scriptedQuery(messages: unknown[]): void {
  queryMock.mockImplementation(
    () =>
      (async function* () {
        for (const m of messages) {
          yield m as never;
        }
      })() as never,
  );
}

function capturedOptions(): Options {
  expect(queryMock).toHaveBeenCalledTimes(1);
  return queryMock.mock.calls[0]![0].options as Options;
}

describe('request shape', () => {
  it('passes the verbatim allowlist env, the planned tool grants, and acceptEdits', async () => {
    scriptedQuery([successResult()]);
    const req = makeReq();
    await runner.runPhase(req);

    const options = capturedOptions();
    // Identity, not just equality: the allowlist object itself must reach the
    // SDK, with nothing merged on top (replace semantics make it the child env).
    expect(options.env).toBe(req.env);
    expect(options.cwd).toBe(req.cwd);
    expect(options.model).toBe('claude-opus-4-8');
    expect(options.allowedTools).toEqual([...CLAUDE_EDIT_TOOLS]);
    expect(options.permissionMode).toBe('acceptEdits');
    expect(typeof options.canUseTool).toBe('function');
    expect(options.systemPrompt).toEqual({ type: 'preset', preset: 'claude_code' });
    expect(options.abortController).toBeInstanceOf(AbortController);
    expect(queryMock.mock.calls[0]![0].prompt).toBe('plan the work');
  });

  it('requests native structured output and forwards maxBudgetUsd when given', async () => {
    scriptedQuery([successResult()]);
    const schema = { type: 'object', properties: { ok: { type: 'boolean' } } };
    await runner.runPhase(makeReq({ schema, maxBudgetUsd: 5 }));

    const options = capturedOptions();
    expect(options.outputFormat).toEqual({ type: 'json_schema', schema });
    expect(options.maxBudgetUsd).toBe(5);
  });

  it('omits outputFormat and maxBudgetUsd when absent (free-form phase)', async () => {
    scriptedQuery([successResult()]);
    await runner.runPhase(makeReq());

    const options = capturedOptions();
    expect('outputFormat' in options).toBe(false);
    expect('maxBudgetUsd' in options).toBe(false);
  });

  it('sets pathToClaudeCodeExecutable from CLAUDE_BIN, or omits it when unresolvable', async () => {
    scriptedQuery([successResult()]);
    await runner.runPhase(makeReq({ env: { ...makeReq().env, CLAUDE_BIN: '/opt/claude' } }));
    expect(capturedOptions().pathToClaudeCodeExecutable).toBe('/opt/claude');

    queryMock.mockReset();
    scriptedQuery([successResult()]);
    await runner.runPhase(makeReq());
    expect('pathToClaudeCodeExecutable' in capturedOptions()).toBe(false);
  });
});

describe('env isolation (highest severity, PLAN.md Section 10)', () => {
  it('hands the SDK only the allowlist when the parent env is poisoned', async () => {
    const poisoned = {
      GH_TOKEN: 'leak-gh',
      MATRIX_TOKEN: 'leak-matrix',
      MX_AGENT_SECRET: 'leak-agent',
      ANTHROPIC_API_KEY: 'sk-ok',
      HOME: join(tmp, 'home'),
      PATH: join(tmp, 'bin'),
    };
    const allowlist = safeSubprocessEnv({ allowGhToken: false, runner: 'claude', source: poisoned });
    scriptedQuery([successResult()]);
    await runner.runPhase(makeReq({ env: allowlist }));

    const env = capturedOptions().env as Record<string, string>;
    expect(env).toBe(allowlist);
    expect(env['ANTHROPIC_API_KEY']).toBe('sk-ok');
    expect(env['GH_TOKEN']).toBeUndefined();
    for (const key of Object.keys(env)) {
      expect(key.startsWith('MATRIX_'), key).toBe(false);
      expect(key.startsWith('MX_AGENT_'), key).toBe(false);
    }
  });
});

describe('result mapping', () => {
  it('maps a success result: structured, native usage/cost, rc 0, sessionId', async () => {
    scriptedQuery([
      assistantMsg('editing files'),
      successResult({ structured_output: { decision: 'approve' } }),
    ]);
    const result = await runner.runPhase(makeReq());

    expect(result.ok).toBe(true);
    expect(result.rc).toBe(0);
    expect(result.signal).toBe('none');
    expect(result.structured).toEqual({ decision: 'approve' });
    expect(result.usage).toEqual({
      inputTokens: 100,
      outputTokens: 50,
      cachedInputTokens: 10,
      costUsd: 0.42,
    });
    expect(result.sessionId).toBe('sess-1');
  });

  it('tees assistant text to the transcript file as it streams', async () => {
    scriptedQuery([assistantMsg('first'), assistantMsg('second'), successResult()]);
    const req = makeReq();
    const result = await runner.runPhase(req);

    expect(result.transcriptText).toBe('first\nsecond\n');
    expect(readFileSync(req.transcriptPath, 'utf8')).toBe('first\nsecond\n');
  });

  it('falls back to the result text when no assistant text streamed', async () => {
    scriptedQuery([successResult({ result: '```json\n{"ok":true}\n```' })]);
    const req = makeReq();
    const result = await runner.runPhase(req);

    expect(result.transcriptText).toBe('```json\n{"ok":true}\n```');
    expect(readFileSync(req.transcriptPath, 'utf8')).toBe('```json\n{"ok":true}\n```');
  });

  it("maps the native budget cap to signal 'budget' (fail fast, no nudge)", async () => {
    scriptedQuery([errorResult('error_max_budget_usd')]);
    const result = await runner.runPhase(makeReq());

    expect(result.ok).toBe(false);
    expect(result.rc).not.toBe(0);
    expect(result.signal).toBe('budget');
  });

  it("maps schema-retry exhaustion to a plain failure (signal 'none' → invoker nudges)", async () => {
    // 0.3.173 has no maxStructuredOutputRetries option; exhaustion surfaces
    // only as this result subtype ([VERIFY] resolution, PLAN.md step 6).
    scriptedQuery([errorResult('error_max_structured_output_retries')]);
    const result = await runner.runPhase(makeReq());

    expect(result.ok).toBe(false);
    expect(result.rc).not.toBe(0);
    expect(result.signal).toBe('none');
    expect(result.structured).toBeNull();
  });

  it('treats a stream that ends without a result message as a crashed run', async () => {
    scriptedQuery([assistantMsg('partial work')]);
    const result = await runner.runPhase(makeReq());

    expect(result.ok).toBe(false);
    expect(result.rc).toBe(1);
    expect(result.signal).toBe('none');
    expect(result.transcriptText).toBe('partial work\n');
  });

  it('keeps captured output and reports rc 1 when the SDK throws (crashed-CLI parity)', async () => {
    queryMock.mockImplementation(
      () =>
        (async function* () {
          yield assistantMsg('began') as never;
          throw new Error('spawn ENOENT');
        })() as never,
    );
    const req = makeReq();
    const result = await runner.runPhase(req);

    expect(result.ok).toBe(false);
    expect(result.rc).toBe(1);
    expect(result.signal).toBe('none');
    expect(result.transcriptText).toBe('began\n');
    expect(readFileSync(req.transcriptPath, 'utf8')).toContain('[claude runner error] Error: spawn ENOENT');
  });
});

describe('timeout / cancellation', () => {
  it("bridges the parent signal to the SDK abortController and maps timeout to signal 'timeout'", async () => {
    const controller = new AbortController();
    queryMock.mockImplementation(
      () =>
        (async function* () {
          yield assistantMsg('working') as never;
          controller.abort(new Error('phase timeout'));
          throw new Error('This operation was aborted');
        })() as never,
    );
    const result = await runner.runPhase(makeReq({ signal: controller.signal }));

    expect(capturedOptions().abortController?.signal.aborted).toBe(true);
    expect(result.signal).toBe('timeout');
    expect(result.rc).toBe(124);
    expect(result.ok).toBe(false);
    expect(result.transcriptText).toBe('working\n');
  });

  it("maps a non-timeout abort to signal 'cancelled'", async () => {
    const controller = new AbortController();
    controller.abort(new Error('user requested stop'));
    queryMock.mockImplementation(
      () =>
        (async function* () {
          throw new Error('This operation was aborted');
        })() as never,
    );
    const result = await runner.runPhase(makeReq({ signal: controller.signal }));

    expect(result.signal).toBe('cancelled');
    expect(result.ok).toBe(false);
  });
});

describe('denyGitGh (caps.perToolHook)', () => {
  const denied = [
    'git status',
    'git push origin main',
    'cd /repo && gh pr create',
    'echo done; git commit -am x',
    'echo `gh auth token`',
    'echo $(git rev-parse HEAD)',
    'env GH_TOKEN=x gh api /user',
    'command git log',
  ];
  const allowed = [
    'pnpm test',
    'cargo build && cargo test',
    'echo github actions',
    'mygit status',
    'pip install ghapi',
    'rg "git" src/',
  ];

  it.each(denied)('denies Bash: %s', async (command) => {
    const verdict = await denyGitGh('Bash', { command }, { signal: new AbortController().signal, toolUseID: 't1' });
    expect(verdict.behavior).toBe('deny');
    if (verdict.behavior === 'deny') {
      expect(verdict.message).toContain('orchestrator owns all git/gh');
    }
  });

  it.each(allowed)('allows Bash: %s', async (command) => {
    const verdict = await denyGitGh('Bash', { command }, { signal: new AbortController().signal, toolUseID: 't1' });
    expect(verdict.behavior).toBe('allow');
  });

  it('allows the granted non-Bash tools untouched', async () => {
    for (const tool of ['Read', 'Write', 'Edit', 'Glob', 'Grep']) {
      const input = { file_path: '/x/git/config.ts' };
      const verdict = await denyGitGh(tool, input, { signal: new AbortController().signal, toolUseID: 't1' });
      expect(verdict.behavior).toBe('allow');
      if (verdict.behavior === 'allow') {
        expect(verdict.updatedInput).toBe(input);
      }
    }
  });
});

describe('resolveClaudeBin (adw/_exec.py:201-213 parity)', () => {
  it('prefers the CLAUDE_BIN override verbatim', () => {
    expect(resolveClaudeBin({ CLAUDE_BIN: '/opt/claude', PATH: '/usr/bin' })).toBe('/opt/claude');
  });

  it('finds an executable named claude on the allowlist PATH', () => {
    const bin = join(tmp, 'bin', 'claude');
    writeFileSync(bin, '#!/bin/sh\n', { mode: 0o755 });
    expect(resolveClaudeBin({ PATH: `${join(tmp, 'empty')}:${join(tmp, 'bin')}` })).toBe(bin);
  });

  it('falls back to the well-known install locations under HOME', () => {
    const local = join(tmp, 'home', '.claude', 'local');
    mkdirSync(local, { recursive: true });
    const bin = join(local, 'claude');
    writeFileSync(bin, '#!/bin/sh\n', { mode: 0o755 });
    expect(resolveClaudeBin({ PATH: join(tmp, 'bin'), HOME: join(tmp, 'home') })).toBe(bin);
  });

  it('returns undefined when nothing resolves (SDK falls back to its built-in)', () => {
    expect(resolveClaudeBin({ PATH: join(tmp, 'bin'), HOME: join(tmp, 'home') })).toBeUndefined();
  });
});

describe('caps', () => {
  it('matches the PLAN.md Section 5 claude column', () => {
    expect(runner.id).toBe('claude');
    expect(runner.caps).toEqual(CLAUDE_CAPS);
    expect(CLAUDE_CAPS).toEqual({
      nativeSchema: true,
      perToolHook: true,
      envIsolation: 'explicit-no-inherit',
      costUsd: true,
      nativeBudget: true,
      resume: true,
    });
  });
});
