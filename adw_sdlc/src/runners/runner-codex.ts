/**
 * Runner #2: `codex` via `@openai/codex-sdk` (PLAN.md roadmap step 7,
 * Sections 4.3-2 and 5).
 *
 * The secret boundary: `CodexOptions.env`, when set, REPLACES the spawned
 * Codex CLI's environment (verified on the installed 0.139.0
 * `dist/index.js:231-240` — the override is assigned onto `{}`, never onto
 * `process.env`). Omitting it flips the SDK to full `process.env` inherit,
 * so this adapter ALWAYS passes the allowlist (enforced by the
 * always-passes-env unit test, the SDK-built-child-env spawn test, and
 * scripts/check-adw-sdlc-env.sh). The `apiKey` option is deliberately
 * unused: the SDK injects it into the child env as CODEX_API_KEY
 * (dist/index.js:244-245), routing a credential around the allowlist —
 * CODEX_API_KEY/OPENAI_API_KEY ride RUNNER_ENV_ALLOW instead, and
 * ChatGPT-login mode needs only HOME (~/.codex/auth.json; CODEX_HOME is
 * allowlisted so callers can point it at a scrubbed dir).
 *
 * Step-7 [VERIFY] resolutions:
 * - Tier model ids: gpt-5.4-mini / gpt-5.4 / gpt-5.5 confirmed current
 *   (Codex models endpoint cache of 2026-05-31 + the OpenAI pricing docs);
 *   the newest generations dropped the `-codex` suffix (last was
 *   gpt-5.3-codex). All support effort low/medium/high/xhigh.
 * - ChatGPT-login minimal env: HOME only (auth.json under ~/.codex);
 *   API-key mode: CODEX_API_KEY or OPENAI_API_KEY ("provide an API key
 *   through a supported auth env var", verified in the 0.139.0 binary).
 * - Native-binary preflight: the Codex constructor resolves the lockstep
 *   vendored binary and throws "Unable to locate Codex CLI binaries" when
 *   the platform package is absent; construction happens inside runPhase's
 *   try so that surfaces as a failed PhaseResult (crashed-CLI parity),
 *   never an exception out of the seam.
 * - outputSchema robustness: AgentMessageItem.text is documented as "JSON
 *   when structured output is requested" but JSON-only output is not
 *   contractual — parse defensively; the invoker's fenced-JSON fallback +
 *   single nudge own anything non-conforming.
 */

import { appendFileSync, writeFileSync } from 'node:fs';

import { Codex } from '@openai/codex-sdk';
import type { ThreadItem, Usage } from '@openai/codex-sdk';

import type {
  AgentRunner,
  PhaseRequest,
  PhaseResult,
  PhaseUsage,
  RunnerCaps,
} from '../invoker.js';
import { costUsd } from '../pricing.js';
import { abortKind, TIMEOUT_RC } from './shared.js';

/**
 * PLAN.md Section 5, codex column. Tool/permission control is COARSE —
 * workspace-write sandbox + approvalPolicy 'never', no per-tool veto
 * (perToolHook false); cost is token-only (costUsd false → pricing.ts);
 * no native budget gate.
 */
export const CODEX_CAPS: RunnerCaps = {
  nativeSchema: true,
  perToolHook: false,
  envIsolation: 'explicit-no-inherit',
  costUsd: false,
  nativeBudget: false,
  resume: true,
};

/**
 * Resolve the Codex CLI binary: the CODEX_BIN override (read from the
 * ALLOWLIST env, never process.env) or undefined, which lets the SDK use the
 * vendored `@openai/codex` binary it ships in lockstep. Unlike
 * resolveClaudeBin there is deliberately NO PATH/HOME search: a `codex` found
 * on PATH can be any version, and the SDK↔binary lockstep pin (PLAN.md D1)
 * is exactly what such a search would silently break.
 */
export function resolveCodexBin(env: Record<string, string | undefined>): string | undefined {
  const override = env['CODEX_BIN'];
  return override !== undefined && override !== '' ? override : undefined;
}

/**
 * Codex token counts mirror the OpenAI API: input_tokens INCLUDES
 * cached_input_tokens, and output_tokens INCLUDES reasoning_output_tokens.
 * PhaseUsage follows the claude adapter's disjoint convention (inputTokens
 * excludes cache reads), so subtract before mapping — costUsd() then prices
 * non-cached input + cache reads + output without double counting, and
 * reasoningTokens stays an informational subset of outputTokens.
 *
 * Counts come from the CLI's JSONL stream, not from code the lockstep pin
 * controls at runtime, so each field is checked like the claude adapter
 * checks its SDK usage — a drifted/missing field degrades to undefined
 * instead of NaN-poisoning the token math and the priced cost.
 */
function usageOf(usage: Usage, model: string): PhaseUsage {
  const raw = usage as unknown as Partial<Record<string, unknown>>;
  const count = (key: string): number | undefined => {
    const value = raw[key];
    return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
  };
  const input = count('input_tokens');
  const cached = count('cached_input_tokens');
  const output = count('output_tokens');
  const reasoning = count('reasoning_output_tokens');

  const phaseUsage: PhaseUsage = {};
  if (input !== undefined) phaseUsage.inputTokens = Math.max(0, input - (cached ?? 0));
  if (output !== undefined) phaseUsage.outputTokens = output;
  if (cached !== undefined) phaseUsage.cachedInputTokens = cached;
  if (reasoning !== undefined) phaseUsage.reasoningTokens = reasoning;
  phaseUsage.costUsd = costUsd(model, phaseUsage);
  return phaseUsage;
}

/** JSON.parse the final agent message; null for prose/non-object payloads (seam contract). */
function parseStructured(finalResponse: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(finalResponse);
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // Not JSON — the invoker's fenced-JSON fallback owns it.
  }
  return null;
}

/**
 * File-only transcript note for non-message thread items, so the log reads
 * like today's CLI transcript while transcriptText stays assistant-text-only
 * (a trailing fenced JSON block must keep parsing in the invoker fallback).
 */
function itemNote(item: ThreadItem): string {
  switch (item.type) {
    case 'reasoning':
      return `[reasoning] ${item.text}\n`;
    case 'command_execution': {
      const rc = item.exit_code !== undefined ? ` rc ${item.exit_code}` : '';
      const output =
        item.aggregated_output === '' || item.aggregated_output.endsWith('\n')
          ? item.aggregated_output
          : `${item.aggregated_output}\n`;
      return `[command ${item.status}${rc}] ${item.command}\n${output}`;
    }
    case 'file_change':
      return `[file_change ${item.status}] ${item.changes
        .map((change) => `${change.kind} ${change.path}`)
        .join(', ')}\n`;
    case 'mcp_tool_call':
      return `[mcp ${item.server}.${item.tool} ${item.status}]${
        item.error !== undefined ? ` ${item.error.message}` : ''
      }\n`;
    case 'web_search':
      return `[web_search] ${item.query}\n`;
    case 'todo_list':
      return `[todo] ${item.items.map((todo) => `${todo.completed ? '[x]' : '[ ]'} ${todo.text}`).join('; ')}\n`;
    case 'error':
      return `[codex error] ${item.message}\n`;
    default:
      return '';
  }
}

class CodexRunner implements AgentRunner {
  readonly id = 'codex' as const;
  readonly caps = CODEX_CAPS;

  async runPhase(req: PhaseRequest): Promise<PhaseResult> {
    writeFileSync(req.transcriptPath, '', 'utf8');
    const tee = (text: string): void => {
      if (text !== '') {
        appendFileSync(req.transcriptPath, text, 'utf8');
      }
    };

    let transcriptText = '';
    let finalResponse = '';
    let usage: Usage | null = null;
    let threadId: string | undefined;
    let turnFailed: string | undefined;

    try {
      const codexBin = resolveCodexBin(req.env);
      // Verbatim allowlist, ALWAYS passed: with env set the SDK builds the
      // child env from it alone (replace semantics); omitted, it would copy
      // all of process.env (dist/index.js:234-239) — the fail-open this
      // adapter exists to prevent.
      const codex = new Codex({
        env: req.env,
        ...(codexBin !== undefined ? { codexPathOverride: codexBin } : {}),
      });
      const thread = codex.startThread({
        model: req.model,
        sandboxMode: 'workspace-write',
        workingDirectory: req.cwd,
        skipGitRepoCheck: true,
        approvalPolicy: 'never',
        ...(req.reasoning !== undefined ? { modelReasoningEffort: req.reasoning } : {}),
      });
      const { events } = await thread.runStreamed(req.prompt, {
        signal: req.signal,
        ...(req.schema !== undefined ? { outputSchema: req.schema } : {}),
      });

      for await (const event of events) {
        if (event.type === 'thread.started') {
          threadId = event.thread_id;
        } else if (event.type === 'item.completed') {
          if (event.item.type === 'agent_message') {
            finalResponse = event.item.text;
            if (event.item.text !== '') {
              const text = `${event.item.text}\n`;
              transcriptText += text;
              tee(text);
            }
          } else {
            tee(itemNote(event.item));
          }
        } else if (event.type === 'turn.completed') {
          usage = event.usage;
        } else if (event.type === 'turn.failed') {
          turnFailed = event.error.message;
          break;
        } else if (event.type === 'error') {
          tee(`[codex stream error] ${event.message}\n`);
        }
      }
    } catch (err) {
      if (req.signal.aborted) {
        return this.failed(req, transcriptText, abortKind(req.signal), TIMEOUT_RC, finalResponse, usage, threadId);
      }
      // Mirror a crashed CLI run (adw/_phases.py:482-516): keep the captured
      // output, report a nonzero rc, and let the invoker parse/nudge/fail.
      // A missing native binary (constructor throw) lands here too.
      tee(`\n[codex runner error] ${String(err)}\n`);
      return this.failed(req, transcriptText, 'none', 1, finalResponse, usage, threadId);
    }

    if (req.signal.aborted) {
      return this.failed(req, transcriptText, abortKind(req.signal), TIMEOUT_RC, finalResponse, usage, threadId);
    }
    if (turnFailed !== undefined) {
      // codex has no native budget cap (caps.nativeBudget false), so every
      // turn failure stays signal 'none' and the invoker's single nudge
      // applies exactly as to a failed CLI run. File only — see itemNote.
      tee(`\n[codex turn.failed] ${turnFailed}\n`);
      return this.failed(req, transcriptText, 'none', 1, finalResponse, usage, threadId);
    }
    if (usage === null) {
      tee('\n[codex runner error] stream ended without turn.completed\n');
      return this.failed(req, transcriptText, 'none', 1, finalResponse, null, threadId);
    }

    return {
      ok: true,
      structured: parseStructured(finalResponse),
      transcriptText,
      usage: usageOf(usage, req.model),
      rc: 0,
      signal: 'none',
      ...(threadId !== undefined ? { sessionId: threadId } : {}),
    };
  }

  private failed(
    req: PhaseRequest,
    transcriptText: string,
    signal: PhaseResult['signal'],
    rc: number,
    finalResponse: string,
    usage: Usage | null,
    threadId: string | undefined,
  ): PhaseResult {
    return {
      ok: false,
      // A final agent message received before the abort/failure still carries
      // the structured payload through, so the invoker's parse-first
      // semantics (run-phase.ts, mirroring adw/_phases.py:507-513) can accept
      // a completed run — the signal still reports what happened and the
      // invoker stays the policy owner.
      structured: parseStructured(finalResponse),
      transcriptText,
      usage: usage !== null ? usageOf(usage, req.model) : {},
      rc,
      signal,
      ...(threadId !== undefined ? { sessionId: threadId } : {}),
    };
  }
}

export function createRunner(): AgentRunner {
  return new CodexRunner();
}
