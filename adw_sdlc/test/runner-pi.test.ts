/**
 * pi runner adapter tests (PLAN.md roadmap step 9).
 *
 * The adapter drives the pi CLI's `--mode json` event stream over an
 * orchestrator-owned spawn, so the tests mock node:child_process and assert
 * the THREE step-9 verify criteria directly on the spawn call:
 * - env-allowlist asserted on the spawn (the load-bearing D5 boundary — the
 *   child env is exactly PhaseRequest.env, never an inherit/merge);
 * - event-bus output capture matches today's fenced-JSON contract
 *   (transcriptText is assistant-text-only, trailing fenced JSON included);
 * - native cost/usage accumulation from per-message usage (caps.costUsd).
 *
 * Hermetic: no network, no pi binary, no real child process.
 */

import { EventEmitter } from 'node:events';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { spawnMock } = vi.hoisted(() => ({ spawnMock: vi.fn() }));

vi.mock('node:child_process', () => ({ spawn: spawnMock }));

import type { AgentRunner, PhaseRequest } from '../src/invoker.js';
import { PHASE_TIMEOUT_ABORT_REASON } from '../src/invoker.js';
import { buildPiArgs, createRunner, PI_CAPS, resolvePiBin } from '../src/runners/runner-pi.js';

type FakeChild = EventEmitter & {
  stdout: PassThrough;
  stderr: PassThrough;
  exitCode: number | null;
  killed: boolean;
  kill: ReturnType<typeof vi.fn>;
};

function makeChild(): FakeChild {
  const child = new EventEmitter() as FakeChild;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.exitCode = null;
  child.killed = false;
  child.kill = vi.fn(() => {
    child.killed = true;
    return true;
  });
  return child;
}

/** Script the fake child: emit `lines` on stdout, then close with `code`. */
function scriptChild(lines: string[], code = 0, stderr = ''): void {
  spawnMock.mockImplementation(() => {
    const child = makeChild();
    setImmediate(() => {
      if (stderr !== '') {
        child.stderr.write(stderr);
      }
      for (const line of lines) {
        child.stdout.write(`${line}\n`);
      }
      child.stdout.end();
      child.stderr.end();
      setImmediate(() => {
        child.exitCode = code;
        child.emit('close', code, null);
      });
    });
    return child;
  });
}

const HEADER = JSON.stringify({
  type: 'session',
  id: 'sess-pi-1',
  timestamp: 'now',
  cwd: '/work',
});

/** One assistant message streaming `text` then ending with usage + stop. */
function assistantEvents(
  text: string,
  over: {
    usage?: Record<string, unknown>;
    stopReason?: string;
    errorMessage?: string;
    deltas?: string[];
  } = {},
): string[] {
  const usage = over.usage ?? {
    input: 100,
    output: 20,
    cacheRead: 30,
    cacheWrite: 5,
    cost: { total: 0.012 },
  };
  const message = {
    role: 'assistant',
    content: [{ type: 'text', text }],
    usage,
    stopReason: over.stopReason ?? 'stop',
    ...(over.errorMessage !== undefined ? { errorMessage: over.errorMessage } : {}),
  };
  return [
    JSON.stringify({ type: 'message_start', message: { role: 'assistant', content: [] } }),
    ...(over.deltas ?? [text]).map((delta) =>
      JSON.stringify({
        type: 'message_update',
        message: { role: 'assistant' },
        assistantMessageEvent: { type: 'text_delta', contentIndex: 0, delta },
      }),
    ),
    JSON.stringify({ type: 'message_end', message }),
  ];
}

let tmp: string;
let runner: AgentRunner;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'adw-pi-'));
  runner = createRunner();
  spawnMock.mockReset();
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function makeReq(over: Partial<PhaseRequest> = {}): PhaseRequest {
  return {
    phase: 'plan',
    prompt: 'plan the work',
    model: 'sonnet',
    cwd: join(tmp, 'worktree'),
    env: { PATH: '/usr/bin', HOME: join(tmp, 'home'), PI_BIN: join(tmp, 'bin/pi') },
    transcriptPath: join(tmp, 'transcript.log'),
    signal: new AbortController().signal,
    ...over,
  };
}

describe('caps', () => {
  it('matches the PLAN.md Section 5 pi column', () => {
    expect(runner.id).toBe('pi');
    expect(runner.caps).toEqual({
      nativeSchema: false,
      perToolHook: false,
      envIsolation: 'subprocess-allowlist',
      costUsd: true,
      nativeBudget: false,
      resume: true,
    });
    expect(runner.caps).toBe(PI_CAPS);
  });
});

describe('the spawn (the load-bearing D5 boundary)', () => {
  it('passes EXACTLY the request env — never an inherit/merge of process.env', async () => {
    vi.stubEnv('GH_TOKEN', 'leak-gh');
    vi.stubEnv('MATRIX_TOKEN', 'leak-matrix');
    vi.stubEnv('MX_AGENT_SECRET', 'leak-agent');
    vi.stubEnv('ANTHROPIC_API_KEY', 'leak-unforwarded-key');
    try {
      scriptChild([HEADER, ...assistantEvents('ok')]);
      const req = makeReq();
      await runner.runPhase(req);
      expect(spawnMock).toHaveBeenCalledTimes(1);
      const options = spawnMock.mock.calls[0]![2] as {
        env: Record<string, string>;
        cwd: string;
        stdio: unknown;
      };
      expect(options.env).toBe(req.env); // the allowlist object, verbatim
      expect(options.env['GH_TOKEN']).toBeUndefined();
      expect(options.env['MATRIX_TOKEN']).toBeUndefined();
      expect(options.env['MX_AGENT_SECRET']).toBeUndefined();
      expect(options.env['ANTHROPIC_API_KEY']).toBeUndefined();
      expect(options.cwd).toBe(req.cwd);
      expect(options.stdio).toEqual(['ignore', 'pipe', 'pipe']);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('maps the request onto the Python print-mode invocation, json mode always on', async () => {
    scriptChild([HEADER, ...assistantEvents('ok')]);
    const req = makeReq({ reasoning: 'high' });
    await runner.runPhase(req);
    expect(spawnMock.mock.calls[0]![0]).toBe(req.env['PI_BIN']);
    // adw/_runner.py:43-50 flag order: -p, --mode json, --model, --thinking, prompt.
    expect(spawnMock.mock.calls[0]![1]).toEqual([
      '-p',
      '--mode',
      'json',
      '--model',
      'sonnet',
      '--thinking',
      'high',
      'plan the work',
    ]);
  });

  it('omits --thinking when the request carries no reasoning hint', () => {
    expect(buildPiArgs(makeReq({ prompt: 'p' }))).toEqual([
      '-p',
      '--mode',
      'json',
      '--model',
      'sonnet',
      'p',
    ]);
  });
});

describe('resolvePiBin', () => {
  it('prefers the PI_BIN override without touching PATH', () => {
    expect(resolvePiBin({ PI_BIN: '/opt/pi', PATH: '/usr/bin' })).toBe('/opt/pi');
  });

  it('falls back to a PATH search against the allowlist env', () => {
    const binDir = join(tmp, 'pathbin');
    mkdirSync(binDir, { recursive: true });
    const bin = join(binDir, 'pi');
    writeFileSync(bin, '#!/bin/sh\n', 'utf8');
    chmodSync(bin, 0o755);
    expect(resolvePiBin({ PATH: `${join(tmp, 'nope')}:${binDir}` })).toBe(bin);
    expect(resolvePiBin({ PATH: join(tmp, 'nope') })).toBeUndefined();
    expect(resolvePiBin({})).toBeUndefined();
  });

  it('a missing binary fails the phase as a crashed CLI run, never an exception', async () => {
    const req = makeReq({ env: { PATH: join(tmp, 'nope') } });
    const result = await runner.runPhase(req);
    expect(spawnMock).not.toHaveBeenCalled();
    expect(result.ok).toBe(false);
    expect(result.rc).toBe(1);
    expect(result.signal).toBe('none');
    expect(readFileSync(req.transcriptPath, 'utf8')).toContain('pi binary not found');
  });
});

describe('event-stream capture (the step-9 verify criterion)', () => {
  it('captures assistant text incl. the trailing fenced JSON, session id, and native usage/cost', async () => {
    const reply = 'Plan written.\n```json\n{"spec_file":"specs/x.md","summary":"s"}\n```';
    scriptChild([
      HEADER,
      ...assistantEvents('working on it', {
        usage: { input: 10, output: 2, cacheRead: 1, cost: { total: 0.001 } },
      }),
      JSON.stringify({ type: 'tool_execution_end', toolName: 'edit', isError: false }),
      ...assistantEvents(reply, {
        usage: { input: 100, output: 20, cacheRead: 30, cost: { total: 0.012 } },
      }),
      JSON.stringify({ type: 'agent_end', messages: [] }),
    ]);
    const req = makeReq();
    const result = await runner.runPhase(req);

    expect(result.ok).toBe(true);
    expect(result.rc).toBe(0);
    expect(result.signal).toBe('none');
    expect(result.structured).toBeNull(); // no native schema: the invoker parses
    expect(result.sessionId).toBe('sess-pi-1');
    // Assistant text only, one terminal newline per message — the trailing
    // fenced JSON stays the LAST thing in the text, as parseJson requires.
    expect(result.transcriptText).toBe(`working on it\n${reply}\n`);
    // Tokens and dollars summed across both assistant messages (dollars via
    // toBeCloseTo: 0.001 + 0.012 is inexact in binary floats).
    expect(result.usage).toMatchObject({
      inputTokens: 110,
      outputTokens: 22,
      cachedInputTokens: 31,
    });
    expect(result.usage.costUsd).toBeCloseTo(0.013, 12);
    // Tool notes are file-only: present in the log, absent from transcriptText.
    const log = readFileSync(req.transcriptPath, 'utf8');
    expect(log).toContain('[tool edit completed]');
    expect(result.transcriptText).not.toContain('[tool');
  });

  it('reconciles the authoritative message_end text when deltas were lost', async () => {
    scriptChild([
      HEADER,
      ...assistantEvents('full reply text', { deltas: ['full re'] }),
    ]);
    const result = await runner.runPhase(makeReq());
    expect(result.transcriptText).toBe('full reply text\n');
  });

  it('keeps stderr and non-JSON stdout in the file only', async () => {
    scriptChild(
      ['not json at all', HEADER, ...assistantEvents('ok')],
      0,
      'some warning\n',
    );
    const req = makeReq();
    const result = await runner.runPhase(req);
    expect(result.ok).toBe(true);
    expect(result.transcriptText).toBe('ok\n');
    const log = readFileSync(req.transcriptPath, 'utf8');
    expect(log).toContain('[pi stdout] not json at all');
    expect(log).toContain('[pi stderr] some warning');
  });

  it('ignores user-message events and thinking deltas', async () => {
    scriptChild([
      HEADER,
      JSON.stringify({
        type: 'message_start',
        message: { role: 'user', content: [{ type: 'text', text: 'the prompt' }] },
      }),
      JSON.stringify({
        type: 'message_end',
        message: { role: 'user', content: [{ type: 'text', text: 'the prompt' }] },
      }),
      JSON.stringify({
        type: 'message_update',
        message: { role: 'assistant' },
        assistantMessageEvent: { type: 'thinking_delta', contentIndex: 0, delta: 'hmm' },
      }),
      ...assistantEvents('visible'),
    ]);
    const result = await runner.runPhase(makeReq());
    expect(result.transcriptText).toBe('visible\n');
    expect(result.usage.costUsd).toBe(0.012); // user messages add no usage
  });

  it('degrades drifted usage fields to undefined/null, never NaN', async () => {
    scriptChild([
      HEADER,
      ...assistantEvents('ok', {
        usage: { input: 'many', output: 7, cost: { total: 'expensive' } },
      }),
    ]);
    const result = await runner.runPhase(makeReq());
    expect(result.ok).toBe(true);
    expect(result.usage).toEqual({ outputTokens: 7, costUsd: null });
  });
});

describe('failure mapping (crashed-CLI parity)', () => {
  it('maps a nonzero exit to a failed result with the child rc', async () => {
    scriptChild([HEADER], 143);
    const result = await runner.runPhase(makeReq());
    expect(result.ok).toBe(false);
    expect(result.rc).toBe(143);
    expect(result.signal).toBe('none');
    expect(result.sessionId).toBe('sess-pi-1');
  });

  it("derives failure from the last assistant stopReason ('--mode json' exits 0 on turn errors)", async () => {
    scriptChild([
      HEADER,
      ...assistantEvents('partial', { stopReason: 'error', errorMessage: 'rate limited' }),
    ]);
    const req = makeReq();
    const result = await runner.runPhase(req);
    expect(result.ok).toBe(false);
    expect(result.rc).toBe(1);
    // No native budget cap: every turn error stays 'none' so the invoker's
    // single nudge applies exactly as to a failed CLI run.
    expect(result.signal).toBe('none');
    expect(result.transcriptText).toBe('partial\n');
    expect(readFileSync(req.transcriptPath, 'utf8')).toContain('[pi error] rate limited');
  });

  it('a spawn error becomes a failed result, never an exception out of the seam', async () => {
    spawnMock.mockImplementation(() => {
      const child = makeChild();
      setImmediate(() => child.emit('error', new Error('spawn pi ENOENT')));
      return child;
    });
    const req = makeReq();
    const result = await runner.runPhase(req);
    expect(result.ok).toBe(false);
    expect(result.rc).toBe(1);
    expect(result.signal).toBe('none');
    expect(readFileSync(req.transcriptPath, 'utf8')).toContain('spawn pi ENOENT');
  });
});

describe('abort handling (no-retry-on-timeout feed)', () => {
  it('SIGTERMs the child and reports signal timeout with the CLI-parity rc', async () => {
    const controller = new AbortController();
    let child: FakeChild;
    spawnMock.mockImplementation(() => {
      child = makeChild();
      setImmediate(() => {
        child.stdout.write(`${HEADER}\n`);
        // The phase timer fires mid-run...
        controller.abort(new Error(PHASE_TIMEOUT_ABORT_REASON));
        // ...and the killed child exits like a SIGTERM'd CLI.
        setImmediate(() => {
          child.exitCode = 143;
          child.stdout.end();
          child.stderr.end();
          child.emit('close', 143, null);
        });
      });
      return child;
    });
    const result = await runner.runPhase(makeReq({ signal: controller.signal }));
    expect(child!.kill).toHaveBeenCalledWith('SIGTERM');
    expect(result.ok).toBe(false);
    expect(result.signal).toBe('timeout');
    expect(result.rc).toBe(124);
    expect(result.sessionId).toBe('sess-pi-1');
  });

  it('a non-timeout abort reports cancelled', async () => {
    const controller = new AbortController();
    spawnMock.mockImplementation(() => {
      const child = makeChild();
      setImmediate(() => {
        controller.abort(new Error('user interrupt'));
        setImmediate(() => {
          child.exitCode = 143;
          child.stdout.end();
          child.stderr.end();
          child.emit('close', 143, null);
        });
      });
      return child;
    });
    const result = await runner.runPhase(makeReq({ signal: controller.signal }));
    expect(result.signal).toBe('cancelled');
  });

  it('a pre-aborted request never spawns', async () => {
    const controller = new AbortController();
    controller.abort(new Error(PHASE_TIMEOUT_ABORT_REASON));
    const result = await runner.runPhase(makeReq({ signal: controller.signal }));
    expect(spawnMock).not.toHaveBeenCalled();
    expect(result.ok).toBe(false);
    expect(result.signal).toBe('timeout');
  });

  it('a late abort after completed output keeps the transcript (parse-first parity)', async () => {
    const controller = new AbortController();
    const reply = '```json\n{"ok":true}\n```';
    spawnMock.mockImplementation(() => {
      const child = makeChild();
      setImmediate(() => {
        child.stdout.write(`${HEADER}\n`);
        for (const line of assistantEvents(reply)) {
          child.stdout.write(`${line}\n`);
        }
        controller.abort(new Error(PHASE_TIMEOUT_ABORT_REASON));
        setImmediate(() => {
          child.exitCode = 143;
          child.stdout.end();
          child.stderr.end();
          child.emit('close', 143, null);
        });
      });
      return child;
    });
    const result = await runner.runPhase(makeReq({ signal: controller.signal }));
    expect(result.ok).toBe(false);
    expect(result.signal).toBe('timeout');
    // The invoker owns the policy; the payload must survive the abort.
    expect(result.transcriptText).toContain('{"ok":true}');
    expect(result.usage.costUsd).toBe(0.012);
  });
});
