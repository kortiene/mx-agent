/**
 * Pins the REAL py-engine delegation spawn (PLAN.md roadmap step 10): the
 * step's headline contract — engine=py spawns `python3 adw/issue.py` from
 * REPO_ROOT with the FULL parent environment (no env option: the py engine
 * builds its own secret boundary) — must be asserted on the spawn call
 * itself, not only on the injected runPyEngine seam, or a scrub/interpreter/
 * rc-mapping regression on the DEFAULT engine path would ship green.
 * (Same discipline as the runner suites, which pin every other spawn site.)
 */

import { EventEmitter } from 'node:events';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

const { spawnMock } = vi.hoisted(() => ({ spawnMock: vi.fn() }));

vi.mock('node:child_process', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:child_process')>()),
  spawn: spawnMock,
}));

import { main } from '../src/cli.js';
import { REPO_ROOT } from '../src/common.js';

afterEach(() => {
  spawnMock.mockReset();
  vi.restoreAllMocks();
});

type SpawnOptions = { cwd?: string; stdio?: string; env?: unknown };

/** A child whose lifecycle events fire after the handlers are registered. */
function scriptChild(emit: (child: EventEmitter) => void): EventEmitter {
  const child = new EventEmitter();
  setImmediate(() => emit(child));
  return child;
}

describe('spawnPyEngine (the real py delegation, no injected seam)', () => {
  it('spawns python3 adw/issue.py from REPO_ROOT with the FULL parent env', async () => {
    spawnMock.mockImplementation(() => scriptChild((c) => c.emit('exit', 0, null)));

    const rc = await main(['5', '--yes'], { env: { GH_TOKEN: 'x', MX_AGENT_ENGINE: 'py' } });
    expect(rc).toBe(0);

    expect(spawnMock).toHaveBeenCalledTimes(1);
    const [cmd, args, options] = spawnMock.mock.calls[0] as [string, string[], SpawnOptions];
    expect(cmd).toBe('python3');
    expect(args).toEqual([join(REPO_ROOT, 'adw', 'issue.py'), '5', '--yes']);
    expect(options.cwd).toBe(REPO_ROOT);
    expect(options.stdio).toBe('inherit');
    // The load-bearing inverse of the D5 allowlist: NO env option at all, so
    // the child inherits everything and python scrubs for itself. A
    // safeSubprocessEnv-style "fix" here would break the py engine's own
    // boundary construction.
    expect('env' in options).toBe(false);
  });

  it('maps the child exit code through, and a signal death to rc 1', async () => {
    spawnMock.mockImplementation(() => scriptChild((c) => c.emit('exit', 3, null)));
    expect(await main(['5'], { env: {} })).toBe(3);

    spawnMock.mockImplementation(() => scriptChild((c) => c.emit('exit', null, 'SIGTERM')));
    expect(await main(['5'], { env: {} })).toBe(1);
  });

  it('maps a spawn failure (python3 missing) to a friendly rc-1 AdwError', async () => {
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});
    spawnMock.mockImplementation(() => scriptChild((c) => c.emit('error', new Error('spawn python3 ENOENT'))));
    expect(await main(['5'], { env: {} })).toBe(1);
    expect(stderr).toHaveBeenCalledWith(expect.stringContaining('could not launch the py engine'));
  });
});
