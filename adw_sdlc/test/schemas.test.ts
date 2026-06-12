import { describe, expect, it } from 'vitest';

import { AdwError } from '../src/errors.js';
import {
  ClassifySchema,
  ISSUE_CLASSES,
  PHASE_SCHEMAS,
  ResolveResultSchema,
  ReviewResultSchema,
  parsePhaseResult,
  phaseJsonSchema,
  type SchemaPhase,
} from '../src/schemas.js';

// Field lists from the Python OUTPUT_CONTRACT (adw/_phases.py:397-410) — the
// cross-language drift guard for the structured-output shapes.
const OUTPUT_CONTRACT_FIELDS: Record<SchemaPhase, string[]> = {
  classify: ['issue_class', 'reason'],
  plan: ['plan_file', 'spec_created', 'summary'],
  implement: ['summary', 'files_changed'],
  tests: ['tests_added', 'summary'],
  resolve: ['resolved', 'remaining', 'summary'],
  e2e: ['e2e_added', 'summary'],
  review: ['findings', 'wrote_commit_message', 'wrote_pr_body'],
  patch: ['resolved', 'remaining', 'summary'],
  document: ['docs_updated', 'files', 'summary', 'wrote_commit_message', 'wrote_pr_body'],
};

// One representative agent payload per phase (what a conforming backend emits).
const FIXTURES: Record<SchemaPhase, Record<string, unknown>> = {
  classify: { issue_class: 'feat', reason: 'adds a new command' },
  plan: { plan_file: 'specs/x.md', spec_created: true, summary: 'planned' },
  implement: { summary: 'did it', files_changed: ['src/a.rs', 'src/b.rs'] },
  tests: { tests_added: true, summary: 'two cases' },
  resolve: { resolved: 1, remaining: 0, summary: 'fixed' },
  e2e: { e2e_added: false, summary: 'not warranted' },
  review: {
    findings: [{ severity: 'blocker', description: 'bug', location: 'a.rs:1' }],
    wrote_commit_message: true,
    wrote_pr_body: true,
  },
  patch: { resolved: 2, remaining: 0, summary: 'patched' },
  document: { docs_updated: true, files: ['docs/x.md'], summary: 'docs', wrote_commit_message: true, wrote_pr_body: true },
};

const PHASES = Object.keys(PHASE_SCHEMAS) as SchemaPhase[];

describe('phase schemas', () => {
  it('every phase parses its representative fixture', () => {
    for (const phase of PHASES) {
      const parsed = PHASE_SCHEMAS[phase].safeParse(FIXTURES[phase]);
      expect(parsed.success, `${phase}: ${JSON.stringify(parsed.error?.issues)}`).toBe(true);
    }
  });

  it('declares exactly the OUTPUT_CONTRACT fields', () => {
    for (const phase of PHASES) {
      const schema = phaseJsonSchema(phase);
      const properties = Object.keys((schema as { properties: Record<string, unknown> }).properties);
      expect(properties.sort(), phase).toEqual([...OUTPUT_CONTRACT_FIELDS[phase]].sort());
    }
  });

  it('round-trips through z.toJSONSchema as an object schema', () => {
    for (const phase of PHASES) {
      const schema = phaseJsonSchema(phase);
      expect(schema['type'], phase).toBe('object');
    }
  });

  it('mirrors to_result tolerance: missing keys default', () => {
    // Python to_result fills missing keys via dict.get defaults
    // (adw/_phases.py:293-353); the empty object must parse for every
    // phase except classify (issue_class is hard-required there too).
    for (const phase of PHASES.filter((p) => p !== 'classify')) {
      const parsed = PHASE_SCHEMAS[phase].safeParse({});
      expect(parsed.success, phase).toBe(true);
    }
    expect(ClassifySchema.safeParse({}).success).toBe(false);
  });

  it('mirrors _as_int coercion: counters accept numeric strings, reject garbage', () => {
    expect(ResolveResultSchema.parse({ resolved: '2', remaining: 1 }).resolved).toBe(2);
    expect(ResolveResultSchema.safeParse({ resolved: 'two' }).success).toBe(false);
  });

  it('classify accepts each contract class and rejects others', () => {
    for (const issueClass of ISSUE_CLASSES) {
      expect(ClassifySchema.safeParse({ issue_class: issueClass }).success).toBe(true);
    }
    expect(ClassifySchema.safeParse({ issue_class: 'feature' }).success).toBe(false);
    expect(ClassifySchema.safeParse({ issue_class: '' }).success).toBe(false);
  });

  it('trims whitespace-padded issue_class like Python to_result (adw/_phases.py:299)', () => {
    expect(parsePhaseResult('classify', { issue_class: ' feat ', reason: 'r' }).issue_class).toBe('feat');
    expect(() => parsePhaseResult('classify', { issue_class: '   ' })).toThrow();
  });

  it('review findings default severity to skippable, never crash on extras', () => {
    const parsed = ReviewResultSchema.parse({
      findings: [{ description: 'no severity recorded', extra_key: 'ignored' }],
    });
    expect(parsed.findings[0]?.severity).toBe('skippable');
    expect(parsed.findings[0]).not.toHaveProperty('extra_key'); // stripped, like the tolerant Python reader
  });
});

describe('parsePhaseResult (to_result tolerance parity)', () => {
  it('null list/string fields fall back to defaults (Python `or []` guards)', () => {
    const implement = parsePhaseResult('implement', { summary: null, files_changed: null });
    expect(implement).toEqual({ summary: '', files_changed: [] });
    const document = parsePhaseResult('document', { files: null, docs_updated: true });
    expect(document.files).toEqual([]);
    const plan = parsePhaseResult('plan', { plan_file: null, summary: 'x' });
    expect(plan.plan_file).toBeNull(); // null is the legitimate plan_file value
  });

  it('drops non-dict review findings entries (adw/_phases.py:332)', () => {
    const review = parsePhaseResult('review', {
      findings: [{ severity: 'blocker', description: 'd' }, 'junk', null, 42],
    });
    expect(review.findings).toHaveLength(1);
    expect(review.findings[0]?.severity).toBe('blocker');
  });

  it('raises AdwError on non-object payloads and contract garbage', () => {
    expect(() => parsePhaseResult('resolve', 'not an object')).toThrowError(AdwError);
    expect(() => parsePhaseResult('resolve', [1, 2])).toThrowError(AdwError);
    expect(() => parsePhaseResult('resolve', { resolved: 'two' })).toThrowError(AdwError);
    expect(() => parsePhaseResult('classify', {})).toThrowError(AdwError);
  });
});
