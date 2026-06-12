/**
 * Per-phase result schemas (PLAN.md Section 7), ported from the Python
 * dataclasses + `to_result` coercion in adw/_phases.py:209-353 and the
 * OUTPUT_CONTRACT at adw/_phases.py:397-410.
 *
 * Dual role: (a) the JSON Schema handed to native-schema backends is derived
 * from these via z.toJSONSchema(); (b) the parent ALWAYS re-validates runner
 * output against them (defense in depth), whatever the backend claims.
 *
 * Tolerance mirrors the Python reader where it is load-bearing: missing keys
 * default (to_result uses dict.get defaults throughout) and integer counters
 * coerce from strings (_as_int exists because agents emit "2"). One deliberate
 * tightening per the plan: issue_class is the 7-value enum from
 * OUTPUT_CONTRACT (Python accepts any non-empty string).
 */

import { z } from 'zod';

import { AdwError } from './errors.js';
import type { JsonSchema } from './invoker.js';

export const ISSUE_CLASSES = ['feat', 'fix', 'docs', 'chore', 'ci', 'test', 'refactor'] as const;

/** Counter fields: agents sometimes emit "2"; mirror Python _as_int coercion. */
const count = z.coerce.number().int().default(0);

export const ClassifySchema = z.object({
  issue_class: z.enum(ISSUE_CLASSES),
  reason: z.string().default(''),
});

export const PlanResultSchema = z.object({
  plan_file: z.string().nullable().default(null),
  spec_created: z.boolean().default(false),
  summary: z.string().default(''),
});

export const ImplementResultSchema = z.object({
  summary: z.string().default(''),
  files_changed: z.array(z.string()).default([]),
});

export const TestsResultSchema = z.object({
  tests_added: z.boolean().default(false),
  summary: z.string().default(''),
});

export const ResolveResultSchema = z.object({
  resolved: count,
  remaining: count,
  summary: z.string().default(''),
});

export const E2EResultSchema = z.object({
  e2e_added: z.boolean().default(false),
  summary: z.string().default(''),
});

export const ReviewFindingSchema = z.object({
  // severity drives the patch blocker gate; default mirrors _phases.py:327.
  severity: z.string().default('skippable'),
  description: z.string().default(''),
  location: z.string().default(''),
});

export const ReviewResultSchema = z.object({
  findings: z.array(ReviewFindingSchema).default([]),
  // Commit message / PR body are authored to workspace files, not inlined.
  wrote_commit_message: z.boolean().default(false),
  wrote_pr_body: z.boolean().default(false),
});

export const PatchResultSchema = z.object({
  resolved: count,
  remaining: count,
  summary: z.string().default(''),
});

export const DocumentResultSchema = z.object({
  docs_updated: z.boolean().default(false),
  files: z.array(z.string()).default([]),
  summary: z.string().default(''),
  wrote_commit_message: z.boolean().default(false),
  wrote_pr_body: z.boolean().default(false),
});

export const PHASE_SCHEMAS = {
  classify: ClassifySchema,
  plan: PlanResultSchema,
  implement: ImplementResultSchema,
  tests: TestsResultSchema,
  resolve: ResolveResultSchema,
  e2e: E2EResultSchema,
  review: ReviewResultSchema,
  patch: PatchResultSchema,
  document: DocumentResultSchema,
} as const;

export type SchemaPhase = keyof typeof PHASE_SCHEMAS;

export type ClassifyResult = z.infer<typeof ClassifySchema>;
export type PlanResult = z.infer<typeof PlanResultSchema>;
export type ImplementResult = z.infer<typeof ImplementResultSchema>;
export type TestsResult = z.infer<typeof TestsResultSchema>;
export type ResolveResult = z.infer<typeof ResolveResultSchema>;
export type E2EResult = z.infer<typeof E2EResultSchema>;
export type ReviewFinding = z.infer<typeof ReviewFindingSchema>;
export type ReviewResult = z.infer<typeof ReviewResultSchema>;
export type PatchResult = z.infer<typeof PatchResultSchema>;
export type DocumentResult = z.infer<typeof DocumentResultSchema>;

/**
 * JSON Schema for a phase, for backends with native schema output
 * (claude outputFormat, codex outputSchema, opencode v2 format). Uses zod
 * v4's native conversion — the plan's zod-to-json-schema dep is unnecessary.
 */
export function phaseJsonSchema(phase: SchemaPhase): JsonSchema {
  return z.toJSONSchema(PHASE_SCHEMAS[phase]) as JsonSchema;
}

/**
 * Parse a raw runner payload with to_result's tolerance (adw/_phases.py:293-353):
 * non-object payloads and unparseable values raise AdwError; null-valued fields
 * fall back to their defaults (real agents emit null for empty lists — Python
 * guards every list with `or []`); non-dict entries inside review findings are
 * dropped (adw/_phases.py:332). The schemas themselves stay null-free so
 * phaseJsonSchema() keeps asking backends for the clean canonical shape.
 */
export function parsePhaseResult<P extends SchemaPhase>(
  phase: P,
  data: unknown,
): z.infer<(typeof PHASE_SCHEMAS)[P]> {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new AdwError(`${phase} phase output must be a JSON object`);
  }
  const normalized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    if (value === null) {
      continue; // defaults apply, mirroring `data.get(key, default) or default`
    }
    normalized[key] = value;
  }
  if (typeof normalized['issue_class'] === 'string') {
    // Python strips issue_class before validating (adw/_phases.py:299);
    // without this, " feat " would pass the py engine and fail the ts one.
    normalized['issue_class'] = normalized['issue_class'].trim();
  }
  if (phase === 'review' && Array.isArray(normalized['findings'])) {
    normalized['findings'] = normalized['findings'].filter(
      (f) => typeof f === 'object' && f !== null && !Array.isArray(f),
    );
  }
  const parsed = PHASE_SCHEMAS[phase].safeParse(normalized);
  if (!parsed.success) {
    throw new AdwError(`${phase} phase output does not match its contract: ${parsed.error.message}`, {
      cause: parsed.error,
    });
  }
  return parsed.data as z.infer<(typeof PHASE_SCHEMAS)[P]>;
}
