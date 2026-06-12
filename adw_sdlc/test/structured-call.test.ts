/**
 * The shared classify structured call (PLAN.md D1): messages.parse +
 * zodOutputFormat with a null-parsed_output retry, token accounting, and
 * parent-computed cost (the Anthropic SDK is token-only). The client is
 * injected — no SDK construction, no network, no API key.
 */

import { describe, expect, it, vi } from 'vitest';

import { AdwError } from '../src/errors.js';
import { ClassifySchema } from '../src/schemas.js';
import { structuredCall, type AnthropicLike } from '../src/structured-call.js';

function fakeClient(outputs: Array<unknown>): { client: AnthropicLike; parse: ReturnType<typeof vi.fn> } {
  const parse = vi.fn();
  for (const parsed of outputs) {
    parse.mockResolvedValueOnce({
      parsed_output: parsed,
      usage: { input_tokens: 100, output_tokens: 10, cache_read_input_tokens: 50 },
    });
  }
  return { client: { messages: { parse } }, parse };
}

describe('structuredCall', () => {
  it('returns the schema-validated value with usage and parent-computed cost', async () => {
    const { client, parse } = fakeClient([{ issue_class: 'feat', reason: 'adds a thing' }]);
    const { value, usage } = await structuredCall('classify this', ClassifySchema, { client });
    expect(value).toEqual({ issue_class: 'feat', reason: 'adds a thing' });
    expect(usage.inputTokens).toBe(100);
    expect(usage.outputTokens).toBe(10);
    expect(usage.cachedInputTokens).toBe(50);
    // claude-haiku-4-5 is priced in pricing.ts, so cost is a number.
    expect(usage.costUsd).toBeCloseTo((100 * 1.0 + 10 * 5.0 + 50 * 0.1) / 1_000_000);

    expect(parse).toHaveBeenCalledTimes(1);
    const params = parse.mock.calls[0]![0] as Record<string, unknown>;
    expect(params['model']).toBe('claude-haiku-4-5');
    expect(params['output_config']).toBeDefined();
  });

  it('retries once with a doubled budget when parsed_output is null (refusal/truncation)', async () => {
    const { client, parse } = fakeClient([null, { issue_class: 'fix', reason: '' }]);
    const { value, usage } = await structuredCall('classify this', ClassifySchema, {
      client,
      maxTokens: 256,
    });
    expect(value.issue_class).toBe('fix');
    expect(parse).toHaveBeenCalledTimes(2);
    const second = parse.mock.calls[1]![0] as Record<string, unknown>;
    expect(second['max_tokens']).toBe(512);
    // Tokens from BOTH attempts are accounted.
    expect(usage.inputTokens).toBe(200);
  });

  it('raises AdwError when both attempts return null', async () => {
    const { client, parse } = fakeClient([null, null]);
    await expect(structuredCall('classify this', ClassifySchema, { client })).rejects.toThrow(AdwError);
    expect(parse).toHaveBeenCalledTimes(2);
  });

  it('rejects a parsed payload that fails the Zod schema', async () => {
    const { client } = fakeClient([{ issue_class: 'not-a-class', reason: '' }]);
    await expect(structuredCall('classify this', ClassifySchema, { client })).rejects.toThrow();
  });
});
