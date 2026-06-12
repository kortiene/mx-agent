import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { ENGINE, RUNNER_IDS } from '../src/index.js';

describe('scaffold', () => {
  it('exposes the ts engine identity and the four runner ids', () => {
    expect(ENGINE).toBe('ts');
    expect(RUNNER_IDS).toEqual(['claude', 'codex', 'opencode', 'pi']);
  });

  it('keeps the D3 package invariants (ESM, Node engine floor, optional runner SDKs)', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    expect(pkg.type).toBe('module');
    // Floor set by the locked toolchain, not the plan's original >=20.10:
    // vitest 4's vite 8 requires ^20.19.0 || >=22.12.0.
    expect(pkg.engines.node).toBe('>=20.19');
    // The four runner SDKs must stay optional so installing/selecting one
    // runner never requires the other three (PLAN.md D3); only the classify
    // SDK and Zod are unconditional runtime deps.
    expect(Object.keys(pkg.dependencies).sort()).toEqual(['@anthropic-ai/sdk', 'zod']);
    expect(Object.keys(pkg.optionalDependencies).sort()).toEqual([
      '@anthropic-ai/claude-agent-sdk',
      '@earendil-works/pi-coding-agent',
      '@openai/codex-sdk',
      '@opencode-ai/sdk',
    ]);
  });
});
