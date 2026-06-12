/**
 * Env-isolation tests (PLAN.md Section 10, "highest severity"): with a
 * poisoned parent env, the allowlist the orchestrator hands a runner child
 * must never contain GH_TOKEN or any MATRIX_-/MX_AGENT_-prefixed key.
 */

import { describe, expect, it } from 'vitest';

import { BASE_ENV_ALLOW, ENV_DENY_PREFIXES, RUNNER_ENV_ALLOW, safeSubprocessEnv } from '../src/env.js';

const POISONED: Record<string, string> = {
  HOME: '/home/u',
  USER: 'u',
  PATH: '/bin',
  ANTHROPIC_API_KEY: 'sk-ant-x',
  ANTHROPIC_AUTH_TOKEN: 'tok',
  OPENAI_API_KEY: 'sk-oai-x',
  CODEX_API_KEY: 'sk-codex-x',
  OPENCODE_SERVER_PASSWORD: 'pw',
  GH_TOKEN: 'ghp_secret',
  GH_BIN: '/bin/gh',
  MATRIX_TOKEN: 'syt_secret',
  MATRIX_DEVICE_KEY: 'device',
  MX_AGENT_FOO: 'x',
  MX_AGENT_YES: '1',
  RANDOM_SECRET: 'leakme',
};

describe('safeSubprocessEnv', () => {
  it('withholds GH_TOKEN and every deny-prefixed key in phased mode', () => {
    const env = safeSubprocessEnv({ allowGhToken: false, source: POISONED });
    expect(env).not.toHaveProperty('GH_TOKEN');
    expect(env).not.toHaveProperty('GH_BIN');
    for (const key of Object.keys(env)) {
      for (const prefix of ENV_DENY_PREFIXES) {
        expect(key.startsWith(prefix)).toBe(false);
      }
    }
    // Non-allowlisted keys never pass through, so future secrets are
    // withheld by default.
    expect(env).not.toHaveProperty('RANDOM_SECRET');
  });

  it('forwards only allowlisted keys that are present in the source', () => {
    const env = safeSubprocessEnv({ allowGhToken: false, source: POISONED });
    expect(env['HOME']).toBe('/home/u');
    expect(env['PATH']).toBe('/bin');
    expect(env).not.toHaveProperty('ANTHROPIC_API_KEY'); // provider keys are per-runner, not base
    expect(env).not.toHaveProperty('SHELL'); // allowlisted but absent from source
  });

  it('includes GH_TOKEN/GH_BIN only in one-shot mode (allowGhToken=true)', () => {
    const env = safeSubprocessEnv({ allowGhToken: true, source: POISONED });
    expect(env['GH_TOKEN']).toBe('ghp_secret');
    expect(env['GH_BIN']).toBe('/bin/gh');
    // Deny prefixes still hold even in one-shot mode.
    expect(env).not.toHaveProperty('MATRIX_TOKEN');
    expect(env).not.toHaveProperty('MX_AGENT_FOO');
  });

  it('layers per-runner credential keys onto the base allowlist', () => {
    const claude = safeSubprocessEnv({ allowGhToken: false, runner: 'claude', source: POISONED });
    expect(claude['ANTHROPIC_API_KEY']).toBe('sk-ant-x');
    expect(claude['ANTHROPIC_AUTH_TOKEN']).toBe('tok');
    const codex = safeSubprocessEnv({ allowGhToken: false, runner: 'codex', source: POISONED });
    expect(codex['CODEX_API_KEY']).toBe('sk-codex-x');
    expect(codex['OPENAI_API_KEY']).toBe('sk-oai-x');
    const opencode = safeSubprocessEnv({ allowGhToken: false, runner: 'opencode', source: POISONED });
    expect(opencode['OPENCODE_SERVER_PASSWORD']).toBe('pw');
    // No runner allowlist ever includes a denied or GitHub key.
    for (const keys of Object.values(RUNNER_ENV_ALLOW)) {
      for (const key of keys) {
        expect(ENV_DENY_PREFIXES.some((p) => key.startsWith(p))).toBe(false);
        expect(key).not.toBe('GH_TOKEN');
      }
    }
  });

  it("never hands one provider's credential to another provider's runner", () => {
    // Step-7 review finding: provider keys are per-runner, so the codex
    // (OpenAI) child must not see the Anthropic key or claude/pi knobs, and
    // the claude child must not see the OpenAI/Codex keys. opencode and pi
    // are any-provider backends and legitimately carry both provider keys.
    const codex = safeSubprocessEnv({ allowGhToken: false, runner: 'codex', source: POISONED });
    for (const key of ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_BIN', 'PI_BIN', 'PI_MODEL']) {
      expect(codex, key).not.toHaveProperty(key);
    }
    const claude = safeSubprocessEnv({ allowGhToken: false, runner: 'claude', source: POISONED });
    for (const key of ['OPENAI_API_KEY', 'CODEX_API_KEY', 'CODEX_HOME', 'PI_BIN']) {
      expect(claude, key).not.toHaveProperty(key);
    }
  });

  it('silently drops deny-prefixed keys requested via extraAllow', () => {
    const env = safeSubprocessEnv({
      allowGhToken: false,
      extraAllow: ['MX_AGENT_FOO', 'MATRIX_TOKEN', 'RANDOM_SECRET'],
      source: POISONED,
    });
    expect(env).not.toHaveProperty('MX_AGENT_FOO');
    expect(env).not.toHaveProperty('MATRIX_TOKEN');
    expect(env['RANDOM_SECRET']).toBe('leakme'); // explicit, non-denied extra is honored
  });

  it('keeps base ∪ runner row aligned with the flat adw/_exec.py allowlist for the ported runners', () => {
    expect(BASE_ENV_ALLOW).toEqual(['HOME', 'USER', 'PATH', 'SHELL', 'TERM', 'LANG', 'LC_ALL', 'TMPDIR']);
    // Python's _BASE_ENV_ALLOW (adw/_exec.py:97-112) = base + these six; its
    // runners are claude and pi, so each of their TS unions must still cover
    // every key the Python pipeline would have forwarded to that runner.
    const pythonExtras = ['ANTHROPIC_API_KEY', 'PI_BIN', 'CLAUDE_BIN', 'CLAUDE_CODE_PATH', 'PI_MODEL', 'PI_THINKING'];
    const union = new Set([...RUNNER_ENV_ALLOW.claude, ...RUNNER_ENV_ALLOW.pi]);
    for (const key of pythonExtras) {
      expect(union.has(key), key).toBe(true);
    }
  });
});
