/**
 * Tests for the orchestrator-owned git/gh layer (port of adw/test_git.py).
 * The exec layer is mocked; no real git/gh runs.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/exec.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/exec.js')>();
  return { ...actual, capture: vi.fn(), ghJson: vi.fn(), note: vi.fn() };
});

import { capture, ghJson } from '../src/exec.js';
import {
  ciStatus,
  commitAll,
  createOrCheckoutBranch,
  createPr,
  prForBranch,
  prNumberFromUrl,
  push,
  squashMerge,
} from '../src/git.js';

const captureMock = vi.mocked(capture);
const ghJsonMock = vi.mocked(ghJson);

const ok = { returncode: 0, stdout: '', stderr: '' };
const fail = { returncode: 1, stdout: '', stderr: 'boom' };

beforeEach(() => {
  captureMock.mockReset();
  ghJsonMock.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('createOrCheckoutBranch', () => {
  it('switches to an existing local branch', () => {
    captureMock.mockImplementation((cmd) => {
      if (cmd[1] === 'show-ref') {
        return ok; // branch exists locally
      }
      return ok;
    });
    expect(createOrCheckoutBranch('feat/5-x', 'main')).toEqual({ ok: true, error: null });
    const switchCall = captureMock.mock.calls.find((c) => c[0][1] === 'switch');
    expect(switchCall?.[0]).toEqual(['git', 'switch', 'feat/5-x']);
  });

  it('creates a missing branch from origin/<base>', () => {
    captureMock.mockImplementation((cmd) => (cmd[1] === 'show-ref' ? fail : ok));
    expect(createOrCheckoutBranch('feat/5-x', 'main').ok).toBe(true);
    const switchCall = captureMock.mock.calls.find((c) => c[0][1] === 'switch');
    expect(switchCall?.[0]).toEqual(['git', 'switch', '-c', 'feat/5-x', 'origin/main']);
  });

  it('reports a failed switch', () => {
    captureMock.mockImplementation((cmd) => (cmd[1] === 'switch' ? fail : ok));
    expect(createOrCheckoutBranch('feat/5-x', 'main')).toEqual({ ok: false, error: 'boom' });
  });

  it('prints instead of running under dry-run', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    expect(createOrCheckoutBranch('feat/5-x', 'main', true).ok).toBe(true);
    expect(captureMock).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledWith('[dry-run] git switch -c feat/5-x origin/main');
  });
});

describe('commitAll', () => {
  it('treats a clean tree as a no-op success', () => {
    captureMock.mockReturnValue({ returncode: 0, stdout: '', stderr: '' });
    expect(commitAll('msg')).toEqual({ ok: true, error: null });
    expect(captureMock).toHaveBeenCalledTimes(1); // only the status probe
  });

  it('stages and commits when the tree is dirty', () => {
    captureMock.mockImplementation((cmd) =>
      cmd[1] === 'status' ? { returncode: 0, stdout: ' M x.rs\n', stderr: '' } : ok,
    );
    expect(commitAll('msg').ok).toBe(true);
    const cmds = captureMock.mock.calls.map((c) => c[0][1]);
    expect(cmds).toContain('add');
    expect(cmds).toContain('commit');
  });

  it('surfaces a commit failure', () => {
    captureMock.mockImplementation((cmd) => {
      if (cmd[1] === 'status') {
        return { returncode: 0, stdout: ' M x.rs\n', stderr: '' };
      }
      return cmd[1] === 'commit' ? fail : ok;
    });
    expect(commitAll('msg')).toEqual({ ok: false, error: 'boom' });
  });
});

describe('push', () => {
  it('pushes with upstream and reports failures', () => {
    captureMock.mockReturnValueOnce(ok);
    expect(push('feat/5-x').ok).toBe(true);
    expect(captureMock.mock.calls[0]?.[0]).toEqual(['git', 'push', '-u', 'origin', 'feat/5-x']);
    captureMock.mockReturnValueOnce(fail);
    expect(push('feat/5-x')).toEqual({ ok: false, error: 'boom' });
  });
});

describe('prForBranch / createPr', () => {
  it('returns the first open PR url, else null', () => {
    ghJsonMock.mockReturnValueOnce([{ url: 'https://x/pull/7' }]);
    expect(prForBranch('b', '/bin/gh', 'o/r')).toBe('https://x/pull/7');
    ghJsonMock.mockReturnValueOnce([]);
    expect(prForBranch('b', '/bin/gh', 'o/r')).toBeNull();
  });

  it('parses the created PR number from the trailing url line', () => {
    captureMock.mockReturnValueOnce({
      returncode: 0,
      stdout: 'some banner\nhttps://github.com/o/r/pull/42\n',
      stderr: '',
    });
    expect(createPr('b', 't', 'body', 'main', '/bin/gh', 'o/r')).toEqual({
      number: 42,
      url: 'https://github.com/o/r/pull/42',
      error: null,
    });
  });

  it('reports gh failures', () => {
    captureMock.mockReturnValueOnce(fail);
    expect(createPr('b', 't', 'body', 'main', '/bin/gh', 'o/r').error).toBe('boom');
  });
});

describe('ciStatus', () => {
  it('maps an unparseable query to unknown and an empty rollup to none', () => {
    ghJsonMock.mockReturnValueOnce(null);
    expect(ciStatus(7, '/bin/gh', 'o/r').state).toBe('unknown');
    ghJsonMock.mockReturnValueOnce({ statusCheckRollup: [] });
    expect(ciStatus(7, '/bin/gh', 'o/r').state).toBe('none');
  });

  it('reports failure with the failing job names', () => {
    ghJsonMock.mockReturnValueOnce({
      statusCheckRollup: [
        { name: 'build', status: 'COMPLETED', conclusion: 'SUCCESS' },
        { name: 'test', status: 'COMPLETED', conclusion: 'FAILURE' },
        { context: 'lint', state: 'ERROR' },
      ],
    });
    const status = ciStatus(7, '/bin/gh', 'o/r');
    expect(status.state).toBe('failure');
    expect(status.failingJobs.map((j) => j.name)).toEqual(['test', 'lint']);
  });

  it('reports pending for queued/in-progress/expected checks', () => {
    ghJsonMock.mockReturnValueOnce({
      statusCheckRollup: [
        { name: 'build', status: 'IN_PROGRESS', conclusion: '' },
        { name: 'done', status: 'COMPLETED', conclusion: 'SUCCESS' },
      ],
    });
    expect(ciStatus(7, '/bin/gh', 'o/r').state).toBe('pending');
    ghJsonMock.mockReturnValueOnce({ statusCheckRollup: [{ context: 'ext', state: 'EXPECTED' }] });
    expect(ciStatus(7, '/bin/gh', 'o/r').state).toBe('pending');
  });

  it('reports success when every check concluded green', () => {
    ghJsonMock.mockReturnValueOnce({
      statusCheckRollup: [
        { name: 'build', status: 'COMPLETED', conclusion: 'SUCCESS' },
        { context: 'ext', state: 'SUCCESS' },
      ],
    });
    expect(ciStatus(7, '/bin/gh', 'o/r').state).toBe('success');
  });
});

describe('squashMerge', () => {
  it('merges with --squash --delete-branch and honors dry-run', () => {
    captureMock.mockReturnValueOnce(ok);
    expect(squashMerge(42, '/bin/gh', 'o/r').ok).toBe(true);
    expect(captureMock.mock.calls[0]?.[0]).toEqual([
      '/bin/gh', 'pr', 'merge', '42', '--squash', '--delete-branch', '--repo', 'o/r',
    ]);
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    expect(squashMerge(42, '/bin/gh', 'o/r', true).ok).toBe(true);
    expect(log).toHaveBeenCalled();
    expect(captureMock).toHaveBeenCalledTimes(1); // dry-run ran nothing new
  });
});

describe('prNumberFromUrl', () => {
  it('extracts trailing numbers and rejects everything else', () => {
    expect(prNumberFromUrl('https://github.com/o/r/pull/42')).toBe(42);
    expect(prNumberFromUrl('https://github.com/o/r/pull/42/')).toBe(42);
    expect(prNumberFromUrl('')).toBeNull();
    expect(prNumberFromUrl('https://github.com/o/r/pulls')).toBeNull();
  });
});
