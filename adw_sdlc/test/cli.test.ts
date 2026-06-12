/**
 * Engine/runner selection wiring (PLAN.md roadmap step 10, D4): the CLI must
 * resolve MX_AGENT_ENGINE / --engine (default py until cutover), delegate py
 * runs to adw/issue.py verbatim, and on the ts engine validate
 * MX_AGENT_RUNNER / --runner over the four-runner registry and bind the
 * loaded adapter into orchestrator.run. Unknown engine/runner values throw,
 * mirroring adw/_orchestrator.py:557-559.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  DEFAULT_ENGINE,
  extractEngineFlag,
  main,
  parseCliArgs,
  resolveEngineId,
  splitPassthru,
  type CliDeps,
} from '../src/cli.js';
import { AdwError, RunnerNotInstalledError } from '../src/errors.js';
import type { AgentRunner } from '../src/invoker.js';
import { createMockRunner } from '../src/runners/runner-mock.js';

afterEach(() => {
  vi.restoreAllMocks();
});

function cliDeps(over: Partial<CliDeps> = {}): CliDeps {
  return {
    env: { PATH: '/bin' },
    runPyEngine: vi.fn(async () => 0),
    loadRunner: vi.fn(async (id) => createMockRunner({ id }) as AgentRunner),
    runIssue: vi.fn(async () => 0),
    ...over,
  };
}

/** Silence the expected `error: …` line and capture it for assertions. */
function muteStderr(): ReturnType<typeof vi.spyOn> {
  return vi.spyOn(console, 'error').mockImplementation(() => {});
}

describe('resolveEngineId', () => {
  it('defaults to py until cutover', () => {
    expect(DEFAULT_ENGINE).toBe('py');
    expect(resolveEngineId(undefined)).toBe('py');
    expect(resolveEngineId(null)).toBe('py');
    expect(resolveEngineId('')).toBe('py');
  });

  it('accepts the two engines', () => {
    expect(resolveEngineId('py')).toBe('py');
    expect(resolveEngineId('ts')).toBe('ts');
  });

  it('throws on unknown values (fail loud, never guess)', () => {
    expect(() => resolveEngineId('rust')).toThrow(AdwError);
    expect(() => resolveEngineId('TS')).toThrow(/unknown engine: 'TS'/);
  });
});

describe('splitPassthru / extractEngineFlag', () => {
  it('splits at the first --', () => {
    expect(splitPassthru(['5', '--yes', '--', '--model', 'x'])).toEqual([
      ['5', '--yes'],
      ['--model', 'x'],
    ]);
    expect(splitPassthru(['5'])).toEqual([['5'], []]);
  });

  it('removes --engine in both spellings; the last occurrence wins', () => {
    expect(extractEngineFlag(['5', '--engine', 'ts', '--yes'])).toEqual({
      engine: 'ts',
      rest: ['5', '--yes'],
    });
    expect(extractEngineFlag(['--engine=py', '5'])).toEqual({ engine: 'py', rest: ['5'] });
    expect(extractEngineFlag(['--engine=py', '--engine', 'ts', '5'])).toEqual({
      engine: 'ts',
      rest: ['5'],
    });
    expect(extractEngineFlag(['5'])).toEqual({ rest: ['5'] });
  });

  it('rejects a dangling --engine', () => {
    expect(() => extractEngineFlag(['5', '--engine'])).toThrow(/--engine requires a value/);
  });
});

describe('parseCliArgs', () => {
  it('parses the issue number and accepts free-form notes', () => {
    const parsed = parseCliArgs(['5', 'fix', 'the', 'thing']);
    expect(parsed.issue).toBe(5);
    expect(parsed.notes).toEqual(['fix', 'the', 'thing']);
    expect(parsed.runner).toBeUndefined();
    expect(parsed.options).toEqual({});
  });

  it('requires a numeric issue', () => {
    expect(() => parseCliArgs([])).toThrow(/missing issue number/);
    expect(() => parseCliArgs(['abc'])).toThrow(/issue must be a number/);
  });

  it('maps every phased flag onto RunOptions (seconds become milliseconds)', () => {
    const parsed = parseCliArgs([
      '7',
      '--runner', 'codex',
      '--phases', 'plan,implement',
      '--adw-id', 'a1b2c3d4',
      '--resume',
      '--no-progress',
      '--inherit-env',
      '--max-resolve', '5',
      '--max-patch', '1',
      '--max-ci-fix', '9',
      '--ci-poll-interval', '10',
      '--ci-max-polls', '7',
      '--test-cmd', 'cargo test -p x',
      '--model', 'm-1',
      '--repo', 'o/r',
      '--base', 'dev',
      '--timeout', '60',
      '--no-verify',
      '--force',
      '--allow-dirty',
      '-y',
      '--dry-run',
      '--max-budget-usd', '2.5',
    ]);
    expect(parsed.issue).toBe(7);
    expect(parsed.runner).toBe('codex');
    expect(parsed.options).toEqual({
      phases: 'plan,implement',
      adwId: 'a1b2c3d4',
      resume: true,
      noProgress: true,
      inheritEnv: true,
      maxResolve: 5,
      maxPatch: 1,
      maxCiFix: 9,
      ciPollIntervalMs: 10_000,
      ciMaxPolls: 7,
      testCmd: 'cargo test -p x',
      model: 'm-1',
      repo: 'o/r',
      base: 'dev',
      timeoutMs: 60_000,
      verify: false,
      force: true,
      allowDirty: true,
      yes: true,
      dryRun: true,
      maxBudgetUsd: 2.5,
    });
  });

  it('accepts --flag=value spellings', () => {
    const parsed = parseCliArgs(['5', '--runner=opencode', '--timeout=30', '--yes']);
    expect(parsed.runner).toBe('opencode');
    expect(parsed.options.timeoutMs).toBe(30_000);
    expect(parsed.options.yes).toBe(true);
  });

  it('defaults --test-cmd and --repo from the environment like adw/issue.py', () => {
    const parsed = parseCliArgs(['5'], { MX_AGENT_TEST_CMD: 'cargo test -p y', REPO: 'a/b' });
    expect(parsed.options.testCmd).toBe('cargo test -p y');
    expect(parsed.options.repo).toBe('a/b');
    // An explicit flag still wins over the env default.
    const explicit = parseCliArgs(['5', '--test-cmd', 'x', '--repo', 'c/d'], {
      MX_AGENT_TEST_CMD: 'cargo test -p y',
      REPO: 'a/b',
    });
    expect(explicit.options.testCmd).toBe('x');
    expect(explicit.options.repo).toBe('c/d');
  });

  it('rejects malformed values, missing values, and unknown flags', () => {
    expect(() => parseCliArgs(['5', '--timeout', 'soon'])).toThrow(/--timeout expects an integer/);
    expect(() => parseCliArgs(['5', '--max-budget-usd', 'lots'])).toThrow(/expects a number/);
    expect(() => parseCliArgs(['5', '--model'])).toThrow(/--model requires a value/);
    expect(() => parseCliArgs(['5', '--resume=please'])).toThrow(/does not take a value/);
    expect(() => parseCliArgs(['5', '--frobnicate'])).toThrow(/unknown flag: --frobnicate/);
  });

  it('rejects py-only flags with a pointer back to the py engine', () => {
    for (const flag of ['--one-shot', '--print-prompt', '--json']) {
      expect(() => parseCliArgs(['5', flag])).toThrow(/py-engine option/);
    }
    expect(() => parseCliArgs(['5', '--template', 'x.md'])).toThrow(/py-engine option/);
    expect(() => parseCliArgs(['5', '--log-dir=/tmp/x'])).toThrow(/py-engine option/);
    expect(() => parseCliArgs(['5', '--thinking', 'high'])).toThrow(/py-engine option/);
  });
});

describe('main — engine dispatch', () => {
  it('delegates to the py engine by default, forwarding argv verbatim', async () => {
    const deps = cliDeps({ runPyEngine: vi.fn(async () => 3) });
    // --runner codex and the passthru are forwarded untouched: the py engine
    // applies its own validation (pi|claude) exactly as a direct invocation.
    const rc = await main(['5', '--runner', 'codex', '--yes', '--', '--model', 'x'], deps);
    expect(rc).toBe(3);
    expect(deps.runPyEngine).toHaveBeenCalledWith(['5', '--runner', 'codex', '--yes', '--', '--model', 'x']);
    expect(deps.loadRunner).not.toHaveBeenCalled();
    expect(deps.runIssue).not.toHaveBeenCalled();
  });

  it('strips --engine from the argv forwarded to the py engine', async () => {
    const deps = cliDeps();
    await main(['--engine', 'py', '5', '--yes'], deps);
    expect(deps.runPyEngine).toHaveBeenCalledWith(['5', '--yes']);
    await main(['--engine=py', '5'], deps);
    expect(deps.runPyEngine).toHaveBeenLastCalledWith(['5']);
  });

  it('binds the selected runner into orchestrator.run on the ts engine', async () => {
    const runner = createMockRunner({ id: 'opencode' });
    const loadRunner = vi.fn(async () => runner as AgentRunner);
    const runIssue = vi.fn(async () => 0);
    const deps = cliDeps({ loadRunner: loadRunner as unknown as CliDeps['loadRunner'], runIssue });

    const rc = await main(['--engine', 'ts', '9', '--runner', 'opencode', '--yes', '--timeout', '30'], deps);
    expect(rc).toBe(0);
    expect(loadRunner).toHaveBeenCalledWith('opencode');
    expect(runIssue).toHaveBeenCalledTimes(1);
    const [issue, boundRunner, options] = runIssue.mock.calls[0] as unknown as [number, AgentRunner, object];
    expect(issue).toBe(9);
    expect(boundRunner).toBe(runner);
    expect(options).toEqual({ yes: true, timeoutMs: 30_000 });
  });

  it('honors MX_AGENT_ENGINE and MX_AGENT_RUNNER from the environment', async () => {
    const deps = cliDeps({ env: { MX_AGENT_ENGINE: 'ts', MX_AGENT_RUNNER: 'codex' } });
    await main(['5', '--yes'], deps);
    expect(deps.loadRunner).toHaveBeenCalledWith('codex');
    expect(deps.runPyEngine).not.toHaveBeenCalled();
  });

  it('lets flags win over the environment for both selectors', async () => {
    const deps = cliDeps({ env: { MX_AGENT_ENGINE: 'py', MX_AGENT_RUNNER: 'codex' } });
    await main(['--engine', 'ts', '5', '--runner', 'pi', '--yes'], deps);
    expect(deps.runPyEngine).not.toHaveBeenCalled();
    expect(deps.loadRunner).toHaveBeenCalledWith('pi');
  });

  it('defaults the ts runner to claude (the cutover-gate runner)', async () => {
    const deps = cliDeps({ env: { MX_AGENT_ENGINE: 'ts' } });
    await main(['5', '--yes'], deps);
    expect(deps.loadRunner).toHaveBeenCalledWith('claude');
  });

  it('fails loud on an unknown engine', async () => {
    const stderr = muteStderr();
    const deps = cliDeps();
    expect(await main(['--engine', 'rust', '5'], deps)).toBe(1);
    expect(stderr).toHaveBeenCalledWith(expect.stringContaining("unknown engine: 'rust'"));
    expect(await main(['5'], cliDeps({ env: { MX_AGENT_ENGINE: 'go' } }))).toBe(1);
    expect(deps.runPyEngine).not.toHaveBeenCalled();
    expect(deps.runIssue).not.toHaveBeenCalled();
  });

  it('fails loud on an unknown runner under the ts engine', async () => {
    const stderr = muteStderr();
    const deps = cliDeps({ env: { MX_AGENT_ENGINE: 'ts' } });
    expect(await main(['5', '--runner', 'gemini'], deps)).toBe(1);
    expect(stderr).toHaveBeenCalledWith(expect.stringContaining("unknown runner: 'gemini'"));
    expect(deps.loadRunner).not.toHaveBeenCalled();
  });

  it('rejects runner passthru flags on the ts engine (no runner command line)', async () => {
    muteStderr();
    const deps = cliDeps({ env: { MX_AGENT_ENGINE: 'ts' } });
    expect(await main(['5', '--yes', '--', '--permission-mode', 'acceptEdits'], deps)).toBe(1);
    expect(deps.runIssue).not.toHaveBeenCalled();
  });

  it('surfaces RunnerNotInstalledError as a friendly rc-1 failure', async () => {
    const stderr = muteStderr();
    const deps = cliDeps({
      env: { MX_AGENT_ENGINE: 'ts' },
      loadRunner: vi.fn(async () => {
        throw new RunnerNotInstalledError('codex', '@openai/codex-sdk');
      }),
    });
    expect(await main(['5', '--runner', 'codex'], deps)).toBe(1);
    expect(stderr).toHaveBeenCalledWith(expect.stringContaining('not installed'));
  });

  it('maps AdwError from the run itself to rc 1 but lets bugs propagate', async () => {
    muteStderr();
    const adwFail = cliDeps({
      env: { MX_AGENT_ENGINE: 'ts' },
      runIssue: vi.fn(async () => {
        throw new AdwError('working tree is dirty');
      }),
    });
    expect(await main(['5', '--yes'], adwFail)).toBe(1);

    const bug = cliDeps({
      env: { MX_AGENT_ENGINE: 'ts' },
      runIssue: vi.fn(async () => {
        throw new TypeError('boom');
      }),
    });
    await expect(main(['5', '--yes'], bug)).rejects.toThrow(TypeError);
  });

  it('returns the orchestrator rc unchanged', async () => {
    const deps = cliDeps({ env: { MX_AGENT_ENGINE: 'ts' }, runIssue: vi.fn(async () => 2) });
    expect(await main(['5', '--yes'], deps)).toBe(2);
  });
});
