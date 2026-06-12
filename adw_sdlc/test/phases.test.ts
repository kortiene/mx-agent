/**
 * Phase catalog, conditional gates, and prompt composition (port of the
 * matching adw/test_phases.py coverage, plus the TS-only footer gating for
 * native-schema backends).
 */

import { describe, expect, it } from 'vitest';

import { AdwError } from '../src/errors.js';
import {
  AGENT_PHASES,
  buildFooter,
  commitMessagePath,
  composePhasePrompt,
  gateConditional,
  gateDocument,
  gateE2e,
  OUTPUT_CONTRACT,
  parsePhases,
  PHASE_PREAMBLE_SHARED,
  prBodyPath,
  templatePath,
} from '../src/phases.js';
import { PHASE_SCHEMAS, parsePhaseResult } from '../src/schemas.js';
import { AdwState } from '../src/state.js';

const state = new AdwState({ adwId: 'a1b2c3d4' });

describe('parsePhases', () => {
  it('defaults to the full chain and validates subsets', () => {
    expect(parsePhases(undefined)).toEqual([...AGENT_PHASES]);
    expect(parsePhases('plan, implement')).toEqual(['plan', 'implement']);
  });

  it('rejects unknown and empty phase lists', () => {
    expect(() => parsePhases('plan,bogus')).toThrow(AdwError);
    expect(() => parsePhases(' , ')).toThrow(AdwError);
  });
});

describe('conditional gates', () => {
  it('runs e2e only on whole-word cross-boundary hints', () => {
    expect(gateE2e('adds IPC handling to the daemon').runIt).toBe(true);
    // Incidental substrings must not trip the gate: the path adw/_exec.py
    // must not match "exec"; "design"/"assignee" must not match a signing hint.
    expect(gateE2e('refactor helpers in adw/_exec.py').runIt).toBe(false);
    expect(gateE2e('redesign the assignee picker').runIt).toBe(false);
    expect(gateE2e('').runIt).toBe(false);
  });

  it('runs document for doc-like files or user-visible surface hints', () => {
    expect(gateDocument('internal change', ['README.md']).runIt).toBe(true);
    expect(gateDocument('internal change', ['docs/guide.md']).runIt).toBe(true);
    expect(gateDocument('add a new cli flag', ['src/main.rs']).runIt).toBe(true);
    expect(gateDocument('tighten internal lifetimes', ['src/lib.rs']).runIt).toBe(false);
  });

  it('dispatches via gateConditional and fails loudly for non-conditional phases', () => {
    expect(gateConditional('e2e', 'touches the scheduler').runIt).toBe(true);
    expect(gateConditional('document', 'x', ['wiki/Home.md']).runIt).toBe(true);
    expect(() => gateConditional('plan', 'x')).toThrow(AdwError);
  });
});

describe('templatePath', () => {
  it('prefers .claude/commands for the claude runner, else .pi/prompts', () => {
    expect(templatePath('claude', 'classify')).toContain('.claude/commands/classify.md');
    expect(templatePath('pi', 'classify')).toContain('.pi/prompts/classify.md');
    expect(templatePath('codex', 'classify')).toContain('.pi/prompts/classify.md');
  });
});

describe('prompt composition', () => {
  it('composes preamble + reframing + body + JSON footer for fenced-JSON backends', () => {
    const prompt = composePhasePrompt('implement', ['specs/x.md', 'issue ctx'], state, 'pi', true);
    expect(prompt.startsWith(PHASE_PREAMBLE_SHARED)).toBe(true);
    expect(prompt).toContain('Scope for this phase: make the code change only.');
    expect(prompt).toContain('## Required output');
    expect(prompt).toContain(OUTPUT_CONTRACT['implement']);
  });

  it('omits the JSON contract (but keeps the prompt) for native-schema backends', () => {
    const prompt = composePhasePrompt('implement', ['specs/x.md', 'issue ctx'], state, 'claude', false);
    expect(prompt.startsWith(PHASE_PREAMBLE_SHARED)).toBe(true);
    expect(prompt).not.toContain('## Required output');
    expect(prompt).not.toContain('```json');
  });

  it('keeps artifact-file instructions on BOTH output paths for review/document', () => {
    for (const emitJsonContract of [true, false]) {
      const footer = buildFooter('review', state, emitJsonContract);
      expect(footer).toContain(commitMessagePath(state));
      expect(footer).toContain(prBodyPath(state));
      expect(footer).toContain('wrote_*');
    }
    expect(buildFooter('review', state, true)).toContain('## Required output');
    expect(buildFooter('review', state, false)).not.toContain('## Required output');
    // Non-artifact phases with native schema need no footer at all.
    expect(buildFooter('plan', state, false)).toBe('');
  });

});

describe('contract drift guard', () => {
  it('every OUTPUT_CONTRACT key round-trips through the matching Zod schema', () => {
    // The fenced-JSON contract footer and schemas.ts must describe the same
    // shape: parse each documented example with its phase schema.
    for (const phase of AGENT_PHASES) {
      const example = JSON.parse(
        OUTPUT_CONTRACT[phase]
          .replaceAll('"feat|fix|docs|chore|ci|test|refactor"', '"feat"')
          .replaceAll('"blocker|tech_debt|skippable"', '"blocker"')
          .replaceAll(', "..."', ''),
      );
      expect(() => parsePhaseResult(phase, example), phase).not.toThrow();
      // And the schema declares every key the contract documents.
      const shape = Object.keys(PHASE_SCHEMAS[phase].shape);
      for (const key of Object.keys(example)) {
        expect(shape, `${phase}.${key}`).toContain(key);
      }
    }
  });
});
