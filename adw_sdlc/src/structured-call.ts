/**
 * The shared single-structured-call helper on @anthropic-ai/sdk (PLAN.md D1).
 *
 * classify is the only pure structured phase — its template forbids examining
 * the codebase, so it needs no tools, no shell, and no worktree. It therefore
 * runs IN-PROCESS on the plain Anthropic SDK (messages.parse + zodOutputFormat)
 * with claude-haiku-4-5 by default, regardless of the selected runner; the
 * D5 process boundary does not apply because nothing here can read an env or
 * spawn a child (the SDK only needs ANTHROPIC_API_KEY, which is already on
 * the base allowlist).
 */

import { zodOutputFormat } from '@anthropic-ai/sdk/helpers/zod';
import type { z } from 'zod';

import { AdwError } from './errors.js';
import type { PhaseUsage } from './invoker.js';
import { CLASSIFY_MODEL } from './models.js';
import { costUsd } from './pricing.js';

/** The slice of the Anthropic client structuredCall touches (injectable in tests). */
export interface AnthropicLike {
  messages: {
    parse(params: Record<string, unknown>, options?: { signal?: AbortSignal }): Promise<ParsedMessageLike>;
  };
}

interface ParsedMessageLike {
  parsed_output?: unknown;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
    cache_read_input_tokens?: number | null;
  };
}

export interface StructuredCallOptions {
  model?: string;
  /** Output budget for the reply; the single retry doubles it (truncation guard). */
  maxTokens?: number;
  signal?: AbortSignal;
  /** Injectable client for tests; defaults to a lazily constructed Anthropic(). */
  client?: AnthropicLike;
}

export interface StructuredCallResult<T> {
  value: T;
  usage: PhaseUsage;
}

const STRUCTURED_NUDGE =
  '\n\nRespond with ONLY the required structured output. Do not refuse; pick the closest match.';

/**
 * One schema-constrained call returning a Zod-validated value plus usage
 * (cost parent-computed from pricing.ts — the Anthropic SDK is token-only).
 * `parsed_output` is null on refusal/truncation, so one retry nudges with a
 * doubled max_tokens before failing (PLAN.md Section 7).
 */
export async function structuredCall<S extends z.ZodType>(
  prompt: string,
  schema: S,
  options: StructuredCallOptions = {},
): Promise<StructuredCallResult<z.infer<S>>> {
  const client = options.client ?? (await defaultClient());
  const model = options.model ?? CLASSIFY_MODEL;
  const maxTokens = options.maxTokens ?? 1024;
  const usage: PhaseUsage = {};

  const attempt = async (text: string, budget: number): Promise<unknown> => {
    const message = await client.messages.parse(
      {
        model,
        max_tokens: budget,
        messages: [{ role: 'user', content: text }],
        output_config: { format: zodOutputFormat(schema) },
      },
      options.signal !== undefined ? { signal: options.signal } : undefined,
    );
    accumulateUsage(usage, message);
    return message.parsed_output ?? null;
  };

  let parsed = await attempt(prompt, maxTokens);
  if (parsed === null) {
    parsed = await attempt(prompt + STRUCTURED_NUDGE, maxTokens * 2);
  }
  if (parsed === null) {
    throw new AdwError('structured call returned no parsed output (refusal or truncation) after retry');
  }
  usage.costUsd = costUsd(model, usage);
  return { value: schema.parse(parsed), usage };
}

function accumulateUsage(usage: PhaseUsage, message: ParsedMessageLike): void {
  const u = message.usage;
  if (!u) {
    return;
  }
  if (typeof u.input_tokens === 'number') {
    usage.inputTokens = (usage.inputTokens ?? 0) + u.input_tokens;
  }
  if (typeof u.output_tokens === 'number') {
    usage.outputTokens = (usage.outputTokens ?? 0) + u.output_tokens;
  }
  if (typeof u.cache_read_input_tokens === 'number') {
    usage.cachedInputTokens = (usage.cachedInputTokens ?? 0) + u.cache_read_input_tokens;
  }
}

async function defaultClient(): Promise<AnthropicLike> {
  // Lazy so importing this module never constructs a client (or demands an
  // API key) — only a real un-injected call does.
  const { default: Anthropic } = await import('@anthropic-ai/sdk');
  return new Anthropic() as unknown as AnthropicLike;
}
