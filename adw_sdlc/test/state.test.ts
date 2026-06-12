/**
 * State persistence + the TS half of the cross-language schema-contract
 * test (PLAN.md D4): adw/state.schema.json is the sole contract between the
 * Python and TS engines, validated from BOTH test suites with the same
 * minimal stdlib validator (mirrored from adw/test_state.py).
 */

import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { REPO_ROOT } from '../src/common.js';
import { AdwError } from '../src/errors.js';
import { AdwState, makeAdwId, setAgentsDir, validateAdwId } from '../src/state.js';
import { validate, type Schema } from './helpers/state-schema.js';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'adw-state-'));
  setAgentsDir(tmp);
});

afterEach(() => {
  setAgentsDir(null);
  rmSync(tmp, { recursive: true, force: true });
});

describe('adw ids', () => {
  it('generates valid 8-hex ids', () => {
    const id = makeAdwId();
    expect(id).toMatch(/^[0-9a-f]{8}$/);
    expect(validateAdwId(id)).toBe(id);
  });

  it('rejects malformed ids (path-injection guard)', () => {
    for (const bad of ['', '..', '../../x', 'ABCDEF12', 'a1b2c3d', 'a1b2c3d4e']) {
      expect(() => validateAdwId(bad)).toThrow(AdwError);
    }
    expect(() => new AdwState({ adwId: '../../etc' })).toThrow(AdwError);
  });
});

describe('persistence', () => {
  it('round-trips through save/load with v1 defaults', () => {
    const state = new AdwState({ adwId: 'a1b2c3d4' });
    expect(state.schemaVersion).toBe(1);
    state.issueClass = 'feat';
    state.markDone('setup');
    state.markDone('setup'); // idempotent
    state.save();

    const loaded = AdwState.load('a1b2c3d4');
    expect(loaded).not.toBeNull();
    expect(loaded?.issueClass).toBe('feat');
    expect(loaded?.completedPhases).toEqual(['setup']);
    expect(loaded?.base).toBe('main');
  });

  it('writes all v1 fields (including nulls) like the Python writer', () => {
    new AdwState({ adwId: 'a1b2c3d4' }).save();
    const raw = JSON.parse(readFileSync(join(tmp, 'a1b2c3d4', 'state.json'), 'utf8'));
    for (const key of [
      'adw_id',
      'schema_version',
      'issue_number',
      'issue_class',
      'branch_name',
      'base',
      'plan_file',
      'pr_number',
      'pr_url',
      'commit_message',
      'pr_body',
      'review_findings',
      'completed_phases',
    ]) {
      expect(raw).toHaveProperty(key);
    }
    // Additive fields appear only when set.
    expect(raw).not.toHaveProperty('engine');
    expect(raw).not.toHaveProperty('total_cost_usd');
  });

  it('serializes additive fields when set', () => {
    const state = new AdwState({ adwId: 'a1b2c3d4', engine: 'ts', runner: 'claude', totalCostUsd: 0.5 });
    state.save();
    const raw = JSON.parse(readFileSync(state.statePath(), 'utf8'));
    expect(raw.engine).toBe('ts');
    expect(raw.runner).toBe('claude');
    expect(raw.total_cost_usd).toBe(0.5);
  });

  it('loads a Python-written document, dropping unknown keys and junk findings', () => {
    const ws = join(tmp, 'a1b2c3d4');
    mkdirSync(ws, { recursive: true });
    writeFileSync(
      join(ws, 'state.json'),
      JSON.stringify({
        adw_id: 'a1b2c3d4',
        schema_version: 1,
        issue_number: '9',
        issue_class: 'fix',
        branch_name: 'fix/9-x',
        base: 'main',
        plan_file: null,
        pr_number: 42,
        pr_url: 'https://x/pull/42',
        commit_message: 'fix: x',
        pr_body: 'body',
        review_findings: [
          { severity: 'blocker', description: 'bug', location: 'a.rs:1', file: 'a.rs' },
          'not-a-dict',
        ],
        completed_phases: ['setup', 'classify'],
        some_future_key: { nested: true },
      }),
      'utf8',
    );
    const loaded = AdwState.load('a1b2c3d4');
    expect(loaded).not.toBeNull();
    expect(loaded?.prNumber).toBe(42);
    expect(loaded?.completedPhases).toEqual(['setup', 'classify']);
    // Non-object findings are dropped; additive finding keys are preserved.
    expect(loaded?.reviewFindings).toHaveLength(1);
    expect(loaded?.reviewFindings[0]?.['file']).toBe('a.rs');
  });

  it('loads legacy files without schema_version as v1 and tolerates future versions', () => {
    const ws = join(tmp, 'a1b2c3d4');
    mkdirSync(ws, { recursive: true });
    writeFileSync(join(ws, 'state.json'), JSON.stringify({ adw_id: 'a1b2c3d4', issue_number: '9' }), 'utf8');
    expect(AdwState.load('a1b2c3d4')?.schemaVersion).toBe(1);

    writeFileSync(
      join(ws, 'state.json'),
      JSON.stringify({ adw_id: 'a1b2c3d4', schema_version: 99, issue_number: '9' }),
      'utf8',
    );
    const future = AdwState.load('a1b2c3d4');
    expect(future?.schemaVersion).toBe(99);
    expect(future?.issueNumber).toBe('9');
  });

  it('returns null for missing, unreadable, or invalid documents', () => {
    expect(AdwState.load('deadbeef')).toBeNull();
    const ws = join(tmp, 'a1b2c3d4');
    mkdirSync(ws, { recursive: true });
    writeFileSync(join(ws, 'state.json'), 'not json', 'utf8');
    expect(AdwState.load('a1b2c3d4')).toBeNull();
    writeFileSync(join(ws, 'state.json'), JSON.stringify({ no_adw_id: true }), 'utf8');
    expect(AdwState.load('a1b2c3d4')).toBeNull();
  });

  it('sanitizes phase names used as path segments', () => {
    const state = new AdwState({ adwId: 'a1b2c3d4' });
    expect(() => state.phaseDir('../escape')).toThrow(AdwError);
    expect(state.phaseDir('plan')).toBe(join(tmp, 'a1b2c3d4', 'plan'));
  });
});

// --- cross-language schema contract ------------------------------------------

describe('state.schema.json contract', () => {
  const schema = JSON.parse(readFileSync(join(REPO_ROOT, 'adw', 'state.schema.json'), 'utf8')) as Schema;

  it('validates a minimal TS-written state document', () => {
    const state = new AdwState({ adwId: 'a1b2c3d4' });
    state.save();
    const raw = JSON.parse(readFileSync(state.statePath(), 'utf8'));
    expect(validate(raw, schema)).toEqual([]);
  });

  it('validates a fully populated TS-written document, including additive fields', () => {
    const state = new AdwState({
      adwId: 'a1b2c3d4',
      issueNumber: '15',
      issueClass: 'feat',
      branchName: 'feat/15-x',
      base: 'main',
      planFile: 'specs/15-x.md',
      prNumber: 42,
      prUrl: 'https://github.com/kortiene/mx-agent/pull/42',
      commitMessage: 'feat: x',
      prBody: 'body',
      reviewFindings: [{ severity: 'blocker', description: 'd', location: 'a.py:1' }],
      engine: 'ts',
      runner: 'claude',
      totalCostUsd: 1.23,
    });
    state.markDone('setup');
    state.markDone('plan');
    state.save();
    const raw = JSON.parse(readFileSync(state.statePath(), 'utf8'));
    expect(validate(raw, schema)).toEqual([]);
  });

  it('every key the TS writer emits is declared in the schema or additive-legal', () => {
    // The schema permits unknown keys (additionalProperties: true) — assert
    // that explicitly, because the whole coexistence story rests on it.
    expect(schema['additionalProperties']).toBe(true);
    // And every REQUIRED key must be one the TS writer always emits.
    const state = new AdwState({ adwId: 'a1b2c3d4' });
    const written = state.toJSON();
    for (const required of schema['required'] as string[]) {
      expect(written).toHaveProperty(required);
    }
  });

  it('the mini validator itself rejects contract breaks', () => {
    const base = new AdwState({ adwId: 'a1b2c3d4' }).toJSON();
    expect(validate(base, schema)).toEqual([]);
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ adw_id: 'NOTHEX!!' }, 'pattern'],
      [{ schema_version: 0 }, 'minimum'],
      [{ schema_version: '1' }, 'not of type'],
      [{ pr_number: '42' }, 'not of type'],
      // severity is load-bearing for the patch gate, so a finding without it
      // is a contract violation (writers must record it; the reader still
      // coerces tolerantly on resume).
      [{ review_findings: [{ description: 'd' }] }, 'missing required'],
      [{ completed_phases: 'plan' }, 'not of type'],
      [{ review_findings: [['not-an-object']] }, 'not of type'],
    ];
    for (const [mutation, expected] of cases) {
      const errors = validate({ ...base, ...mutation }, schema);
      expect(errors.length, JSON.stringify(mutation)).toBeGreaterThan(0);
      expect(errors.join(' ')).toContain(expected);
    }
    const dropped = { ...base };
    delete dropped['schema_version'];
    expect(validate(dropped, schema).join(' ')).toContain('missing required');
  });
});
