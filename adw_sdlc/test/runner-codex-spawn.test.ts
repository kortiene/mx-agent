/**
 * Secret-withholding proof for the codex runner, asserted on the env the SDK
 * actually BUILDS for its child (PLAN.md Sections 4.3-2, 8 criterion 4, 10):
 * this file deliberately does NOT mock @openai/codex-sdk — it drives the real
 * 0.139.0 CodexExec over a mocked child_process.spawn, so a credential routed
 * around the allowlist object (e.g. via the apiKey option, which the SDK
 * injects as CODEX_API_KEY after applying the env override) could never pass
 * unobserved. Still hermetic: no network, no native binary (CODEX_BIN skips
 * findCodexPath), no real child process.
 */

import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { spawnMock } = vi.hoisted(() => ({ spawnMock: vi.fn() }));

// The SDK imports the BARE 'child_process' specifier (dist/index.js); fs,
// readline, and module stay real — only the process boundary is intercepted.
vi.mock('child_process', () => ({ spawn: spawnMock }));

import { safeSubprocessEnv } from '../src/env.js';
import type { AgentRunner, PhaseRequest } from '../src/invoker.js';
import { createRunner } from '../src/runners/runner-codex.js';

type FakeChild = EventEmitter & {
  stdin: { write: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn> };
  stdout: PassThrough;
  stderr: PassThrough;
  killed: boolean;
  kill: ReturnType<typeof vi.fn>;
};

function fakeChild(lines: string[]): FakeChild {
  const child = new EventEmitter() as FakeChild;
  child.stdin = { write: vi.fn(), end: vi.fn() };
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killed = false;
  child.kill = vi.fn(() => {
    child.killed = true;
    return true;
  });
  // Emit the JSONL stream after the SDK has wired readline + its exit
  // listener (both happen synchronously after spawn returns).
  setImmediate(() => {
    for (const line of lines) {
      child.stdout.write(`${line}\n`);
    }
    child.stdout.end();
    setImmediate(() => child.emit('exit', 0, null));
  });
  return child;
}

const EVENTS = [
  JSON.stringify({ type: 'thread.started', thread_id: 'th-spawn-1' }),
  JSON.stringify({ type: 'turn.started' }),
  JSON.stringify({
    type: 'item.completed',
    item: { id: 'm1', type: 'agent_message', text: '{"ok":true}' },
  }),
  JSON.stringify({
    type: 'turn.completed',
    usage: { input_tokens: 10, cached_input_tokens: 0, output_tokens: 5, reasoning_output_tokens: 0 },
  }),
];

let tmp: string;
let runner: AgentRunner;
let lastChild: FakeChild | undefined;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'adw-codex-spawn-'));
  runner = createRunner();
  spawnMock.mockReset();
  spawnMock.mockImplementation(() => {
    lastChild = fakeChild(EVENTS);
    return lastChild;
  });
  // Poison the REAL parent env: none of these may reach the spawned child.
  vi.stubEnv('GH_TOKEN', 'leak-gh');
  vi.stubEnv('MATRIX_TOKEN', 'leak-matrix');
  vi.stubEnv('MX_AGENT_SECRET', 'leak-agent');
  vi.stubEnv('OPENAI_API_KEY', 'leak-unrequested-key');
});

afterEach(() => {
  vi.unstubAllEnvs();
  rmSync(tmp, { recursive: true, force: true });
});

function makeReq(env: Record<string, string>, over: Partial<PhaseRequest> = {}): PhaseRequest {
  return {
    phase: 'plan',
    prompt: 'plan the work',
    model: 'gpt-5.5',
    cwd: join(tmp, 'worktree'),
    env,
    transcriptPath: join(tmp, 'transcript.log'),
    signal: new AbortController().signal,
    ...over,
  };
}

function spawnedEnv(): Record<string, string> {
  expect(spawnMock).toHaveBeenCalledTimes(1);
  return (spawnMock.mock.calls[0]![2] as { env: Record<string, string> }).env;
}

function spawnedArgs(): string[] {
  return spawnMock.mock.calls[0]![1] as string[];
}

describe('the SDK-built child env (the load-bearing boundary)', () => {
  it('contains the allowlist plus the SDK originator marker and NOTHING from the poisoned parent', async () => {
    const allowlist = safeSubprocessEnv({
      allowGhToken: false,
      runner: 'codex',
      source: {
        HOME: join(tmp, 'home'),
        PATH: join(tmp, 'bin'),
        CODEX_API_KEY: 'sk-requested',
        CODEX_BIN: '/fake/codex',
        GH_TOKEN: 'leak-gh',
        MATRIX_TOKEN: 'leak-matrix',
        MX_AGENT_SECRET: 'leak-agent',
      },
    });
    const result = await runner.runPhase(makeReq(allowlist, { schema: { type: 'object' } }));

    const env = spawnedEnv();
    expect(env['GH_TOKEN']).toBeUndefined();
    for (const key of Object.keys(env)) {
      expect(key.startsWith('MATRIX_'), key).toBe(false);
      expect(key.startsWith('MX_AGENT_'), key).toBe(false);
    }
    expect(env['CODEX_API_KEY']).toBe('sk-requested');
    // Exactly the allowlist + the one benign marker the SDK adds for itself.
    const extras = Object.keys(env).filter((key) => !(key in allowlist));
    expect(extras).toEqual(['CODEX_INTERNAL_ORIGINATOR_OVERRIDE']);

    // The same run, end to end through the real SDK stream parser:
    expect(spawnMock.mock.calls[0]![0]).toBe('/fake/codex');
    expect(result.ok).toBe(true);
    expect(result.structured).toEqual({ ok: true });
    expect(result.sessionId).toBe('th-spawn-1');
    expect(lastChild!.stdin.write).toHaveBeenCalledWith('plan the work');
  });

  it('withholds a parent credential the allowlist did not request (no apiKey side door)', async () => {
    // process.env has OPENAI_API_KEY (stubbed above); the allowlist omits it.
    // If the adapter ever passed CodexOptions.apiKey — or dropped env — the
    // SDK-built child env would carry a key this assertion catches.
    const allowlist = safeSubprocessEnv({
      allowGhToken: false,
      runner: 'codex',
      source: { HOME: join(tmp, 'home'), PATH: join(tmp, 'bin'), CODEX_BIN: '/fake/codex' },
    });
    await runner.runPhase(makeReq(allowlist));

    const env = spawnedEnv();
    expect(env['OPENAI_API_KEY']).toBeUndefined();
    expect(env['CODEX_API_KEY']).toBeUndefined();
    expect(env['GH_TOKEN']).toBeUndefined();
  });

  it('keeps the boundary on the production-default path (no CODEX_BIN → SDK binary resolution)', async () => {
    // Without the override the real CodexExec resolves the vendored lockstep
    // binary in its constructor and may prepend its vendor dirs to the child
    // PATH — the one SDK-side env mutation the CODEX_BIN tests never reach.
    // Where the platform package is absent (e.g. a CI matrix without the
    // optional dep), the constructor throws and the adapter must fail CLOSED
    // as a failed PhaseResult without ever spawning.
    vi.stubEnv('PATH', '/poisoned/parent/path');
    const allowlist = safeSubprocessEnv({
      allowGhToken: false,
      runner: 'codex',
      source: { HOME: join(tmp, 'home'), PATH: join(tmp, 'bin') },
    });
    const req = makeReq(allowlist);
    const result = await runner.runPhase(req);

    if (spawnMock.mock.calls.length === 0) {
      expect(result.ok).toBe(false);
      expect(result.rc).toBe(1);
      expect(result.signal).toBe('none');
    } else {
      const env = spawnedEnv();
      expect(env['GH_TOKEN']).toBeUndefined();
      expect(env['PATH']).toContain(join(tmp, 'bin'));
      expect(env['PATH']).not.toContain('/poisoned/parent/path');
      const extras = Object.keys(env).filter((key) => !(key in allowlist) && key !== 'PATH');
      expect(extras).toEqual(['CODEX_INTERNAL_ORIGINATOR_OVERRIDE']);
      expect(result.ok).toBe(true);
    }
  });

  it('passes the planned coarse-sandbox argv to the real CLI surface', async () => {
    const allowlist = safeSubprocessEnv({
      allowGhToken: false,
      runner: 'codex',
      source: { HOME: join(tmp, 'home'), PATH: join(tmp, 'bin'), CODEX_BIN: '/fake/codex' },
    });
    const req = makeReq(allowlist, { schema: { type: 'object' }, reasoning: 'high' });
    await runner.runPhase(req);

    const args = spawnedArgs();
    expect(args.slice(0, 2)).toEqual(['exec', '--experimental-json']);
    expect(args).toContain('--model');
    expect(args[args.indexOf('--model') + 1]).toBe('gpt-5.5');
    expect(args).toContain('--sandbox');
    expect(args[args.indexOf('--sandbox') + 1]).toBe('workspace-write');
    expect(args).toContain('--cd');
    expect(args[args.indexOf('--cd') + 1]).toBe(req.cwd);
    expect(args).toContain('--skip-git-repo-check');
    expect(args).toContain('--output-schema');
    expect(args).toContain('approval_policy="never"');
    expect(args).toContain('model_reasoning_effort="high"');
  });
});
