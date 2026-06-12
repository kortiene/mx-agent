/**
 * Unit tests for the opencode runner adapter (PLAN.md roadmap step 8).
 *
 * The v2 client and child_process are replaced by vi.mock per the hermetic
 * CI rule (PLAN.md Section 9): no network, no keys, no opencode binary. The
 * spawn-env cases are the highest-severity ones here — the adapter owns the
 * `opencode serve` spawn precisely because the SDK's createOpencodeServer
 * spreads process.env; the env object handed to spawn() IS the D5 boundary,
 * and grandchildren (the agent's tools) inherit it.
 */

import { EventEmitter } from 'node:events';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const {
  spawnMock,
  createClientMock,
  sessionCreateMock,
  sessionPromptMock,
  sessionAbortMock,
  eventSubscribeMock,
} = vi.hoisted(() => ({
  spawnMock: vi.fn(),
  createClientMock: vi.fn(),
  sessionCreateMock: vi.fn(),
  sessionPromptMock: vi.fn(),
  sessionAbortMock: vi.fn(),
  eventSubscribeMock: vi.fn(),
}));

vi.mock('node:child_process', () => ({ spawn: spawnMock }));

vi.mock('@opencode-ai/sdk/v2/client', () => ({
  createOpencodeClient: createClientMock,
}));

import { safeSubprocessEnv } from '../src/env.js';
import { PHASE_TIMEOUT_ABORT_REASON } from '../src/invoker.js';
import type { AgentRunner, PhaseRequest } from '../src/invoker.js';
import {
  createRunner,
  OPENCODE_CAPS,
  OPENCODE_PERMISSION,
  resolveOpencodeBin,
  splitModel,
} from '../src/runners/runner-opencode.js';

/** Minimal stand-in for the `opencode serve` child. */
class FakeProc extends EventEmitter {
  stdout = new EventEmitter();
  stderr = new EventEmitter();
  kill = vi.fn(() => true);
  exitCode: number | null = null;
  killed = false;
}

let tmp: string;
let runner: AgentRunner;
let proc: FakeProc;

const SERVER_URL = 'http://127.0.0.1:53999';

function bannerOnSpawn(stream: 'stdout' | 'stderr' = 'stdout'): void {
  spawnMock.mockImplementation(() => {
    proc = new FakeProc();
    setImmediate(() => {
      proc[stream].emit('data', `opencode server listening on ${SERVER_URL}\n`);
    });
    return proc;
  });
}

function makeInfo(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'msg-1',
    sessionID: 'sess-1',
    role: 'assistant',
    cost: 0.0123,
    tokens: { input: 100, output: 50, reasoning: 20, cache: { read: 10, write: 5 } },
    ...over,
  };
}

function promptResolves(info: Record<string, unknown>, parts: unknown[] = []): void {
  sessionPromptMock.mockResolvedValue({ data: { info, parts }, error: undefined });
}

function makeReq(over: Partial<PhaseRequest> = {}): PhaseRequest {
  return {
    phase: 'plan',
    prompt: 'plan the work',
    model: 'anthropic/claude-opus-4-8',
    cwd: join(tmp, 'worktree'),
    env: { PATH: join(tmp, 'bin'), HOME: join(tmp, 'home'), OPENCODE_BIN: join(tmp, 'opencode') },
    transcriptPath: join(tmp, 'transcript.log'),
    signal: new AbortController().signal,
    ...over,
  };
}

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'adw-runner-opencode-'));
  runner = createRunner();
  spawnMock.mockReset();
  createClientMock.mockReset();
  sessionCreateMock.mockReset();
  sessionPromptMock.mockReset();
  sessionAbortMock.mockReset();
  eventSubscribeMock.mockReset();

  bannerOnSpawn();
  createClientMock.mockImplementation(() => ({
    session: { create: sessionCreateMock, prompt: sessionPromptMock, abort: sessionAbortMock },
    event: { subscribe: eventSubscribeMock },
  }));
  sessionCreateMock.mockResolvedValue({ data: { id: 'sess-1' }, error: undefined });
  sessionAbortMock.mockResolvedValue({ data: true, error: undefined });
  // Default: an SSE stream that never yields (the final-parts replay owns the
  // transcript); individual tests script richer streams.
  eventSubscribeMock.mockResolvedValue({ stream: (async function* () {})() });
  promptResolves(makeInfo());
});

afterEach(async () => {
  await runner.stop?.();
  rmSync(tmp, { recursive: true, force: true });
});

describe('server spawn (the D5 boundary)', () => {
  it('self-spawns opencode serve with the verbatim allowlist plus the authored config, never process.env', async () => {
    const poisoned = {
      GH_TOKEN: 'leak-gh',
      MATRIX_TOKEN: 'leak-matrix',
      MX_AGENT_SECRET: 'leak-agent',
      ANTHROPIC_API_KEY: 'sk-ant',
      OPENCODE_BIN: join(tmp, 'opencode'),
      HOME: join(tmp, 'home'),
      PATH: join(tmp, 'bin'),
    };
    const allowlist = safeSubprocessEnv({ allowGhToken: false, runner: 'opencode', source: poisoned });
    const req = makeReq({ env: allowlist });
    await runner.runPhase(req);

    expect(spawnMock).toHaveBeenCalledTimes(1);
    const [bin, args, options] = spawnMock.mock.calls[0]! as [
      string,
      string[],
      { cwd: string; env: Record<string, string> },
    ];
    expect(bin).toBe(join(tmp, 'opencode'));
    // --port 0 is NOT ephemeral on opencode (falls back to 4096): the adapter
    // draws a random IANA dynamic-range port instead.
    expect(args.slice(0, 4)).toEqual(['serve', '--hostname', '127.0.0.1', '--port']);
    const port = Number(args[4]);
    expect(port).toBeGreaterThanOrEqual(49152);
    expect(port).toBeLessThan(65536);
    expect(options.cwd).toBe(req.cwd);
    expect(options.env['ANTHROPIC_API_KEY']).toBe('sk-ant');
    expect(options.env['GH_TOKEN']).toBeUndefined();
    for (const key of Object.keys(options.env)) {
      expect(key.startsWith('MATRIX_'), key).toBe(false);
      expect(key.startsWith('MX_AGENT_'), key).toBe(false);
    }
    // The only key beyond the allowlist is the config the adapter authors.
    const extra = Object.keys(options.env).filter((key) => !(key in allowlist));
    expect(extra).toEqual(['OPENCODE_CONFIG_CONTENT']);
  });

  it("authors a permission config that denies bash git/gh and never uses 'ask' (headless)", async () => {
    await runner.runPhase(makeReq());

    const env = (spawnMock.mock.calls[0]![2] as { env: Record<string, string> }).env;
    const config = JSON.parse(env['OPENCODE_CONFIG_CONTENT']!) as {
      permission: Record<string, unknown>;
    };
    expect(config.permission).toEqual(OPENCODE_PERMISSION);
    const bash = config.permission['bash'] as Record<string, string>;
    expect(bash['git *']).toBe('deny');
    expect(bash['gh *']).toBe('deny');
    expect(JSON.stringify(config)).not.toContain('"ask"');
  });

  it('reuses one server across phases (sessions are per-phase)', async () => {
    await runner.runPhase(makeReq());
    promptResolves(makeInfo());
    await runner.runPhase(makeReq({ phase: 'implement' }));

    expect(spawnMock).toHaveBeenCalledTimes(1);
    expect(createClientMock).toHaveBeenCalledTimes(1);
    expect(createClientMock).toHaveBeenCalledWith({ baseUrl: SERVER_URL });
    expect(sessionCreateMock).toHaveBeenCalledTimes(2);
  });

  it('accepts the readiness banner on stderr too', async () => {
    bannerOnSpawn('stderr');
    const result = await runner.runPhase(makeReq());
    expect(result.ok).toBe(true);
  });

  it('maps a missing binary to a failed result, never an exception', async () => {
    const result = await runner.runPhase(makeReq({ env: { HOME: join(tmp, 'home'), PATH: join(tmp, 'empty') } }));

    expect(result.ok).toBe(false);
    expect(result.rc).toBe(1);
    expect(result.signal).toBe('none');
    expect(spawnMock).not.toHaveBeenCalled();
    expect(readFileSync(makeReq().transcriptPath, 'utf8')).toContain('opencode binary not found');
  });

  it('retries an exit-before-banner (port collision) on fresh random ports, then fails with the output', async () => {
    spawnMock.mockImplementation(() => {
      proc = new FakeProc();
      setImmediate(() => {
        proc.stderr.emit('data', 'fatal: address in use\n');
        proc.exitCode = 7;
        proc.emit('exit', 7);
      });
      return proc;
    });
    const req = makeReq();
    const result = await runner.runPhase(req);

    expect(result.ok).toBe(false);
    expect(result.rc).toBe(1);
    expect(spawnMock).toHaveBeenCalledTimes(3);
    const log = readFileSync(req.transcriptPath, 'utf8');
    expect(log).toContain('exited with code 7');
    expect(log).toContain('fatal: address in use');
  });

  it('recovers within one phase when a later bind attempt succeeds', async () => {
    let calls = 0;
    spawnMock.mockImplementation(() => {
      proc = new FakeProc();
      calls += 1;
      if (calls === 1) {
        setImmediate(() => proc.emit('exit', 1));
      } else {
        setImmediate(() => proc.stdout.emit('data', `opencode server listening on ${SERVER_URL}\n`));
      }
      return proc;
    });
    const result = await runner.runPhase(makeReq());

    expect(result.ok).toBe(true);
    expect(spawnMock).toHaveBeenCalledTimes(2);
  });

  it('maps a spawn error (ENOENT-style) to a failed result', async () => {
    spawnMock.mockImplementation(() => {
      proc = new FakeProc();
      setImmediate(() => proc.emit('error', new Error('spawn ENOENT')));
      return proc;
    });
    const result = await runner.runPhase(makeReq());

    expect(result.ok).toBe(false);
    expect(result.rc).toBe(1);
  });

  it('fails the phase when the banner line has no parseable url', async () => {
    spawnMock.mockImplementation(() => {
      proc = new FakeProc();
      setImmediate(() => proc.stdout.emit('data', 'opencode server listening somewhere\n'));
      return proc;
    });
    const result = await runner.runPhase(makeReq());

    expect(result.ok).toBe(false);
    expect(proc.kill).toHaveBeenCalled();
  });

  it('retries the spawn on the next phase after a failed start (no poisoned cache)', async () => {
    spawnMock.mockImplementationOnce(() => {
      proc = new FakeProc();
      setImmediate(() => proc.emit('error', new Error('spawn ENOENT')));
      return proc;
    });
    const first = await runner.runPhase(makeReq());
    expect(first.ok).toBe(false);

    promptResolves(makeInfo());
    const second = await runner.runPhase(makeReq());
    expect(second.ok).toBe(true);
    expect(spawnMock).toHaveBeenCalledTimes(2);
  });

  it('stop() kills the self-spawned server and is a no-op before any phase', async () => {
    await runner.stop?.(); // nothing started yet
    await runner.runPhase(makeReq());
    await runner.stop?.();

    expect(proc.kill).toHaveBeenCalledWith('SIGTERM');
  });

  it('does not resurrect a server when stop() lands during the spawn (failed phase, child killed)', async () => {
    let emitBanner: () => void = () => {};
    spawnMock.mockImplementation(() => {
      proc = new FakeProc();
      emitBanner = () => proc.stdout.emit('data', `opencode server listening on ${SERVER_URL}\n`);
      return proc;
    });
    const pending = runner.runPhase(makeReq());
    await new Promise((resolve) => setImmediate(resolve));
    await runner.stop?.();
    emitBanner();
    const result = await pending;

    expect(result.ok).toBe(false);
    expect(proc.kill).toHaveBeenCalledWith('SIGTERM');
    expect(sessionCreateMock).not.toHaveBeenCalled();
  });
});

describe('request shape', () => {
  it('creates a session and prompts with directory, split model, text part, and the parent signal', async () => {
    const req = makeReq();
    await runner.runPhase(req);

    expect(sessionCreateMock).toHaveBeenCalledWith(
      { directory: req.cwd, title: 'adw plan' },
      { signal: req.signal },
    );
    const [body, options] = sessionPromptMock.mock.calls[0]! as [Record<string, unknown>, { signal: AbortSignal }];
    expect(body['sessionID']).toBe('sess-1');
    expect(body['directory']).toBe(req.cwd);
    expect(body['model']).toEqual({ providerID: 'anthropic', modelID: 'claude-opus-4-8' });
    expect(body['parts']).toEqual([{ type: 'text', text: 'plan the work' }]);
    expect('format' in body).toBe(false);
    expect(options.signal).toBe(req.signal);
  });

  it('forwards the schema as format json_schema with one native retry, or omits it', async () => {
    const schema = { type: 'object', properties: { ok: { type: 'boolean' } } };
    await runner.runPhase(makeReq({ schema }));

    const body = sessionPromptMock.mock.calls[0]![0] as Record<string, unknown>;
    expect(body['format']).toEqual({ type: 'json_schema', schema, retryCount: 1 });
  });

  it('omits the model for an unprefixed override (server default provider resolution)', async () => {
    await runner.runPhase(makeReq({ model: 'claude-opus-4-8' }));
    const body = sessionPromptMock.mock.calls[0]![0] as Record<string, unknown>;
    expect('model' in body).toBe(false);
  });
});

describe('result mapping', () => {
  it('maps a success: native structured, native cost, finite-checked disjoint tokens', async () => {
    promptResolves(makeInfo({ structured: { decision: 'approve' } }), [
      { id: 'p1', sessionID: 'sess-1', messageID: 'msg-1', type: 'text', text: '{"decision":"approve"}' },
    ]);
    const result = await runner.runPhase(makeReq());

    expect(result.ok).toBe(true);
    expect(result.rc).toBe(0);
    expect(result.signal).toBe('none');
    expect(result.structured).toEqual({ decision: 'approve' });
    expect(result.sessionId).toBe('sess-1');
    expect(result.usage).toEqual({
      inputTokens: 100,
      outputTokens: 50,
      cachedInputTokens: 10,
      reasoningTokens: 20,
      costUsd: 0.0123,
    });
  });

  it('degrades missing/garbage usage fields to undefined and cost to null (server-drift guard)', async () => {
    promptResolves(makeInfo({ cost: 'oops', tokens: { output: 50, cache: {} } }));
    const result = await runner.runPhase(makeReq());

    expect(result.ok).toBe(true);
    expect(result.usage.inputTokens).toBeUndefined();
    expect(result.usage.cachedInputTokens).toBeUndefined();
    expect(result.usage.outputTokens).toBe(50);
    expect(result.usage.costUsd).toBeNull();
    for (const value of Object.values(result.usage)) {
      expect(Number.isNaN(value as number)).toBe(false);
    }
  });

  it('returns structured null for a non-object structured payload (invoker fallback owns it)', async () => {
    for (const structured of [undefined, null, [1, 2], 'text', 42]) {
      sessionPromptMock.mockReset();
      promptResolves(makeInfo({ structured }));
      const result = await runner.runPhase(makeReq());
      expect(result.ok, String(structured)).toBe(true);
      expect(result.structured, String(structured)).toBeNull();
    }
  });

  it("maps a message error (StructuredOutputError etc.) to a plain failure: signal 'none' → invoker nudges", async () => {
    promptResolves(
      makeInfo({
        error: { name: 'StructuredOutputError', data: { message: 'no valid JSON after retries', retries: 1 } },
      }),
    );
    const req = makeReq();
    const result = await runner.runPhase(req);

    expect(result.ok).toBe(false);
    expect(result.rc).toBe(1);
    expect(result.signal).toBe('none');
    expect(result.sessionId).toBe('sess-1');
    // Usage from the failed attempt still counts toward run totals.
    expect(result.usage.costUsd).toBe(0.0123);
    const log = readFileSync(req.transcriptPath, 'utf8');
    expect(log).toContain('[opencode StructuredOutputError] no valid JSON after retries');
  });

  it('maps an HTTP error envelope from prompt to a failed result', async () => {
    sessionPromptMock.mockResolvedValue({
      data: undefined,
      error: { name: 'NotFoundError', data: { message: 'session gone' } },
    });
    const req = makeReq();
    const result = await runner.runPhase(req);

    expect(result.ok).toBe(false);
    expect(result.rc).toBe(1);
    expect(readFileSync(req.transcriptPath, 'utf8')).toContain('prompt failed');
  });

  it('maps a failed session.create to a failed result', async () => {
    sessionCreateMock.mockResolvedValue({ data: undefined, error: { data: { message: 'bad directory' } } });
    const result = await runner.runPhase(makeReq());

    expect(result.ok).toBe(false);
    expect(result.rc).toBe(1);
    expect(sessionPromptMock).not.toHaveBeenCalled();
  });

  it('keeps captured output and reports rc 1 when the client throws (crashed-CLI parity)', async () => {
    sessionPromptMock.mockRejectedValue(new Error('socket hang up'));
    const req = makeReq();
    const result = await runner.runPhase(req);

    expect(result.ok).toBe(false);
    expect(result.rc).toBe(1);
    expect(result.signal).toBe('none');
    expect(readFileSync(req.transcriptPath, 'utf8')).toContain('[opencode runner error] Error: socket hang up');
  });
});

describe('transcript', () => {
  it('replays the final parts: text (with terminal newline) into transcriptText, tool notes file-only', async () => {
    promptResolves(makeInfo({ structured: { ok: true } }), [
      { id: 'p1', sessionID: 'sess-1', messageID: 'msg-1', type: 'step-start' },
      {
        id: 'p2',
        sessionID: 'sess-1',
        messageID: 'msg-1',
        type: 'tool',
        callID: 'c1',
        tool: 'edit',
        state: { status: 'completed', input: {}, output: 'done', title: 'src/x.ts', metadata: {}, time: { start: 1, end: 2 } },
      },
      { id: 'p3', sessionID: 'sess-1', messageID: 'msg-1', type: 'text', text: '{"ok":true}' },
      {
        id: 'p4',
        sessionID: 'sess-1',
        messageID: 'msg-1',
        type: 'tool',
        callID: 'c2',
        tool: 'bash',
        state: { status: 'error', input: {}, error: 'denied', time: { start: 1, end: 2 } },
      },
    ]);
    const req = makeReq();
    const result = await runner.runPhase(req);

    expect(result.transcriptText).toBe('{"ok":true}\n');
    const log = readFileSync(req.transcriptPath, 'utf8');
    expect(log).toContain('[tool edit completed] src/x.ts');
    expect(log).toContain('[tool bash error] denied');
  });

  it('tees SSE text deltas live and never double-writes against the final-parts replay', async () => {
    const req = makeReq();
    let midPrompt = '';
    eventSubscribeMock.mockResolvedValue({
      stream: (async function* () {
        // The USER message's parts also replay on the bus (observed live) and
        // must never reach an assistant-text-only transcript.
        yield {
          type: 'message.updated',
          properties: { sessionID: 'sess-1', info: { id: 'msg-user', role: 'user' } },
        };
        yield {
          type: 'message.part.updated',
          properties: { part: { id: 'pu', sessionID: 'sess-1', messageID: 'msg-user', type: 'text', text: 'plan the work' } },
        };
        yield {
          type: 'message.updated',
          properties: { sessionID: 'sess-1', info: { id: 'msg-1', role: 'assistant' } },
        };
        yield {
          type: 'message.part.delta',
          properties: { sessionID: 'sess-1', messageID: 'msg-1', partID: 'p1', field: 'text', delta: 'Hello' },
        };
        yield {
          type: 'message.part.updated',
          properties: { part: { id: 'p1', sessionID: 'sess-1', messageID: 'msg-1', type: 'text', text: 'Hello world' } },
        };
        // Another session's traffic must be ignored.
        yield {
          type: 'message.updated',
          properties: { sessionID: 'other', info: { id: 'msg-x', role: 'assistant' } },
        };
        yield {
          type: 'message.part.delta',
          properties: { sessionID: 'other', messageID: 'msg-x', partID: 'px', field: 'text', delta: 'NOPE' },
        };
      })(),
    });
    sessionPromptMock.mockImplementation(async () => {
      // Let the scripted SSE stream drain before the prompt completes.
      await new Promise((resolve) => setTimeout(resolve, 10));
      midPrompt = readFileSync(req.transcriptPath, 'utf8');
      return {
        data: {
          info: makeInfo(),
          parts: [{ id: 'p1', sessionID: 'sess-1', messageID: 'msg-1', type: 'text', text: 'Hello world' }],
        },
        error: undefined,
      };
    });
    const result = await runner.runPhase(req);

    expect(midPrompt).toBe('Hello world');
    expect(result.transcriptText).toBe('Hello world\n');
    expect(readFileSync(req.transcriptPath, 'utf8')).toBe('Hello world\n');
  });

  it('notes SSE tool completions once, file-only, even when the final parts repeat them', async () => {
    const req = makeReq();
    const toolPart = {
      id: 'p2',
      sessionID: 'sess-1',
      messageID: 'msg-1',
      type: 'tool',
      callID: 'c1',
      tool: 'read',
      state: { status: 'completed', input: {}, output: 'ok', title: 'README.md', metadata: {}, time: { start: 1, end: 2 } },
    };
    eventSubscribeMock.mockResolvedValue({
      stream: (async function* () {
        yield {
          type: 'message.updated',
          properties: { sessionID: 'sess-1', info: { id: 'msg-1', role: 'assistant' } },
        };
        yield { type: 'message.part.updated', properties: { part: toolPart } };
      })(),
    });
    sessionPromptMock.mockImplementation(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      return { data: { info: makeInfo(), parts: [toolPart] }, error: undefined };
    });
    const result = await runner.runPhase(req);

    expect(result.transcriptText).toBe('');
    const log = readFileSync(req.transcriptPath, 'utf8');
    expect(log.match(/\[tool read completed\] README\.md/g)).toHaveLength(1);
  });
});

describe('timeout / cancellation', () => {
  it("maps an aborted prompt to signal 'timeout' and stops the session server-side", async () => {
    const controller = new AbortController();
    sessionPromptMock.mockImplementation(() => {
      controller.abort(new Error(PHASE_TIMEOUT_ABORT_REASON));
      return Promise.reject(new Error('This operation was aborted'));
    });
    const req = makeReq({ signal: controller.signal });
    const result = await runner.runPhase(req);

    expect(result.ok).toBe(false);
    expect(result.rc).toBe(124);
    expect(result.signal).toBe('timeout');
    expect(sessionAbortMock).toHaveBeenCalledWith({ sessionID: 'sess-1', directory: req.cwd });
  });

  it("maps a late abort after a completed prompt to 'timeout' but keeps the structured payload (parse-first parity)", async () => {
    const controller = new AbortController();
    sessionPromptMock.mockImplementation(() => {
      const response = { data: { info: makeInfo({ structured: { done: true } }), parts: [] }, error: undefined };
      controller.abort(new Error(PHASE_TIMEOUT_ABORT_REASON));
      return Promise.resolve(response);
    });
    const result = await runner.runPhase(makeReq({ signal: controller.signal }));

    expect(result.ok).toBe(false);
    expect(result.signal).toBe('timeout');
    expect(result.rc).toBe(124);
    expect(result.structured).toEqual({ done: true });
    expect(result.usage.costUsd).toBe(0.0123);
  });

  it("maps a non-timeout abort to signal 'cancelled'", async () => {
    const controller = new AbortController();
    sessionPromptMock.mockImplementation(() => {
      controller.abort(new Error('user requested stop'));
      return Promise.reject(new Error('This operation was aborted'));
    });
    const result = await runner.runPhase(makeReq({ signal: controller.signal }));

    expect(result.signal).toBe('cancelled');
    expect(result.ok).toBe(false);
  });

  it('returns immediately for a pre-aborted signal without spawning a server', async () => {
    const controller = new AbortController();
    controller.abort(new Error(PHASE_TIMEOUT_ABORT_REASON));
    const result = await runner.runPhase(makeReq({ signal: controller.signal }));

    expect(result.signal).toBe('timeout');
    expect(result.rc).toBe(124);
    expect(spawnMock).not.toHaveBeenCalled();
  });
});

describe('resolveOpencodeBin', () => {
  it('prefers the OPENCODE_BIN override, then PATH, then ~/.opencode/bin (allowlist env only)', () => {
    expect(resolveOpencodeBin({ OPENCODE_BIN: '/opt/opencode' })).toBe('/opt/opencode');

    const pathDir = join(tmp, 'pathbin');
    mkdirSync(pathDir, { recursive: true });
    writeFileSync(join(pathDir, 'opencode'), '#!/bin/sh\n');
    chmodSync(join(pathDir, 'opencode'), 0o755);
    expect(resolveOpencodeBin({ PATH: pathDir })).toBe(join(pathDir, 'opencode'));

    const home = join(tmp, 'homedir');
    mkdirSync(join(home, '.opencode/bin'), { recursive: true });
    writeFileSync(join(home, '.opencode/bin/opencode'), '#!/bin/sh\n');
    chmodSync(join(home, '.opencode/bin/opencode'), 0o755);
    expect(resolveOpencodeBin({ HOME: home, PATH: join(tmp, 'nowhere') })).toBe(
      join(home, '.opencode/bin/opencode'),
    );

    expect(resolveOpencodeBin({ HOME: join(tmp, 'nohome'), PATH: join(tmp, 'nowhere') })).toBeUndefined();
  });
});

describe('splitModel', () => {
  it('splits provider/model on the first slash and passes opaque ids through', () => {
    expect(splitModel('anthropic/claude-opus-4-8')).toEqual({
      providerID: 'anthropic',
      modelID: 'claude-opus-4-8',
    });
    expect(splitModel('openrouter/meta/llama-3')).toEqual({
      providerID: 'openrouter',
      modelID: 'meta/llama-3',
    });
    expect(splitModel('claude-opus-4-8')).toEqual({ providerID: '', modelID: 'claude-opus-4-8' });
    expect(splitModel('trailing/')).toEqual({ providerID: '', modelID: 'trailing/' });
  });
});

describe('caps', () => {
  it('matches the PLAN.md Section 5 opencode column', () => {
    expect(runner.id).toBe('opencode');
    expect(runner.caps).toEqual(OPENCODE_CAPS);
    expect(OPENCODE_CAPS).toEqual({
      nativeSchema: true,
      perToolHook: false,
      envIsolation: 'subprocess-allowlist',
      costUsd: true,
      nativeBudget: false,
      resume: true,
    });
  });
});
