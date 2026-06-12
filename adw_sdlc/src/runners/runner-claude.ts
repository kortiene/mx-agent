/**
 * Runner #1: `claude` via `@anthropic-ai/claude-agent-sdk` (PLAN.md roadmap
 * step 6, Sections 4.3-1 and 5).
 *
 * The secret boundary is the SDK's own child process: `options.env` REPLACES
 * `process.env` when set (verified on the installed 0.3.173 `sdk.d.ts`: "this
 * value REPLACES the subprocess environment entirely"), so passing the
 * `safeSubprocessEnv()` allowlist verbatim as `options.env` IS the D5
 * boundary — no bespoke fork. This module must never spread `process.env`
 * (enforced by scripts/check-adw-sdlc-env.sh and the env-isolation tests).
 *
 * Step-6 [VERIFY] resolutions (installed sdk.d.ts, 0.3.173):
 * - CanUseTool: (toolName, input, {signal, toolUseID, ...}) =>
 *   Promise<PermissionResult>; PermissionResult is the allow/deny union with
 *   `updatedInput`/`message`.
 * - PermissionMode: 'default'|'acceptEdits'|'bypassPermissions'|'plan'|
 *   'dontAsk'|'auto' — 'acceptEdits' exists as planned.
 * - There is NO `maxStructuredOutputRetries` option; schema-retry exhaustion
 *   surfaces as the result subtype 'error_max_structured_output_retries',
 *   which this adapter maps to a failed PhaseResult with signal 'none' so the
 *   invoker's single nudge applies (PLAN.md Section 7).
 */

import { accessSync, appendFileSync, constants, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, join } from 'node:path';

import { query } from '@anthropic-ai/claude-agent-sdk';
import type {
  CanUseTool,
  Options,
  SDKMessage,
  SDKResultMessage,
} from '@anthropic-ai/claude-agent-sdk';

import type {
  AgentRunner,
  PhaseRequest,
  PhaseResult,
  PhaseUsage,
  RunnerCaps,
} from '../invoker.js';

/** PLAN.md Section 5, claude column. */
export const CLAUDE_CAPS: RunnerCaps = {
  nativeSchema: true,
  perToolHook: true,
  envIsolation: 'explicit-no-inherit',
  costUsd: true,
  nativeBudget: true,
  resume: true,
};

/**
 * The capability grant (PLAN.md Section 4.2): today's agent is a CLI with
 * full-fs access in the worktree, so the runner must read and edit unattended
 * or every editing phase becomes a no-op.
 */
export const CLAUDE_EDIT_TOOLS = ['Read', 'Write', 'Edit', 'Glob', 'Grep', 'Bash'] as const;

/**
 * rc reported when the parent's signal killed the run. The TS invoker keys
 * off PhaseResult.signal, never this number; 124 is kept only so transcripts
 * read like today's `timeout`-wrapped CLI runs (adw/_phases.py:479).
 */
const TIMEOUT_RC = 124;

/**
 * Best-effort guard for a git/gh invocation at a command position (after ^,
 * a separator, command substitution, or an `env`/`command` prefix). The
 * load-bearing control is GH_TOKEN's absence from the child env — this veto
 * just fails the attempt earlier and louder (PLAN.md Section 4.4).
 */
const GIT_GH_COMMAND = /(^|[\n;&|]|\$\(|`)\s*(?:command\s+|builtin\s+|env\s+(?:\w+=\S*\s+)*)?(?:git|gh)\b/;

/**
 * Per-tool veto (caps.perToolHook): auto-allow the granted tools, deny Bash
 * commands that invoke git/gh — the orchestrator owns all git/gh (PLAN.md
 * Section 3.3; mirrors the PHASE_PREAMBLE_SHARED contract).
 */
export const denyGitGh: CanUseTool = (toolName, input) => {
  if (toolName === 'Bash') {
    const command = typeof input['command'] === 'string' ? (input['command'] as string) : '';
    if (GIT_GH_COMMAND.test(command)) {
      return Promise.resolve({
        behavior: 'deny',
        message:
          'The orchestrator owns all git/gh operations; do not run git or gh. ' +
          'Edit files and run tests only — the pipeline commits, pushes, and opens the PR.',
      });
    }
  }
  return Promise.resolve({ behavior: 'allow', updatedInput: input });
};

/**
 * Resolve the Claude Code binary like the Python pipeline does
 * (adw/_exec.py:201-213): CLAUDE_BIN override, then PATH, then the two
 * well-known install locations. Resolution reads the ALLOWLIST env (the same
 * env the child gets), never process.env. Unlike Python this returns
 * undefined instead of raising when nothing is found: the SDK then uses its
 * own built-in executable ("Uses the built-in executable if not specified"),
 * which is strictly more available than failing.
 */
export function resolveClaudeBin(env: Record<string, string | undefined>): string | undefined {
  const override = env['CLAUDE_BIN'];
  if (override) {
    return override;
  }
  for (const dir of (env['PATH'] ?? '').split(delimiter)) {
    if (dir && isExecutableFile(join(dir, 'claude'))) {
      return join(dir, 'claude');
    }
  }
  const home = env['HOME'] ?? homedir();
  for (const candidate of [join(home, '.claude/local/claude'), join(home, '.local/bin/claude')]) {
    if (isExecutableFile(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

function isExecutableFile(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/** Accumulate the text blocks of an assistant message (the human-readable transcript). */
function assistantText(message: SDKMessage): string {
  if (message.type !== 'assistant') {
    return '';
  }
  const content: unknown = message.message.content;
  if (typeof content === 'string') {
    return content === '' ? '' : `${content}\n`;
  }
  if (!Array.isArray(content)) {
    return '';
  }
  let out = '';
  for (const block of content) {
    if (
      block !== null &&
      typeof block === 'object' &&
      (block as { type?: unknown }).type === 'text' &&
      typeof (block as { text?: unknown }).text === 'string'
    ) {
      out += (block as { text: string }).text;
    }
  }
  return out === '' ? '' : `${out}\n`;
}

function usageOf(result: SDKResultMessage): PhaseUsage {
  const usage: PhaseUsage = { costUsd: result.total_cost_usd };
  const raw = result.usage as unknown as Partial<Record<string, number>>;
  if (typeof raw['input_tokens'] === 'number') usage.inputTokens = raw['input_tokens'];
  if (typeof raw['output_tokens'] === 'number') usage.outputTokens = raw['output_tokens'];
  if (typeof raw['cache_read_input_tokens'] === 'number') {
    usage.cachedInputTokens = raw['cache_read_input_tokens'];
  }
  return usage;
}

function asStructured(value: unknown): Record<string, unknown> | null {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return null;
}

/** Map the parent's abort reason: only the phase timer says "timeout"; anything else is a cancel. */
function abortKind(signal: AbortSignal): 'timeout' | 'cancelled' {
  const reason: unknown = signal.reason;
  const text =
    reason instanceof Error ? `${reason.name} ${reason.message}` : String(reason ?? '');
  return text.toLowerCase().includes('timeout') ? 'timeout' : 'cancelled';
}

class ClaudeRunner implements AgentRunner {
  readonly id = 'claude' as const;
  readonly caps = CLAUDE_CAPS;

  async runPhase(req: PhaseRequest): Promise<PhaseResult> {
    // The SDK takes an AbortController; bridge the orchestrator-owned signal.
    const abortController = new AbortController();
    const forwardAbort = (): void => {
      abortController.abort(req.signal.reason as Error | undefined);
    };
    if (req.signal.aborted) {
      forwardAbort();
    } else {
      req.signal.addEventListener('abort', forwardAbort, { once: true });
    }

    writeFileSync(req.transcriptPath, '', 'utf8');
    const tee = (text: string): void => {
      if (text !== '') {
        appendFileSync(req.transcriptPath, text, 'utf8');
      }
    };

    const claudeBin = resolveClaudeBin(req.env);
    const options: Options = {
      model: req.model,
      cwd: req.cwd,
      // Verbatim allowlist; the SDK passes it to its child as the ENTIRE env.
      env: req.env,
      abortController,
      allowedTools: [...CLAUDE_EDIT_TOOLS],
      permissionMode: 'acceptEdits',
      canUseTool: denyGitGh,
      // Today's `claude -p` runs with Claude Code's default system prompt and
      // CLI-default setting sources; keep both for AS-IS parity.
      systemPrompt: { type: 'preset', preset: 'claude_code' },
      stderr: (data: string) => tee(data),
      ...(claudeBin !== undefined ? { pathToClaudeCodeExecutable: claudeBin } : {}),
      ...(req.schema !== undefined
        ? { outputFormat: { type: 'json_schema' as const, schema: req.schema } }
        : {}),
      ...(req.maxBudgetUsd !== undefined ? { maxBudgetUsd: req.maxBudgetUsd } : {}),
    };

    let transcriptText = '';
    let result: SDKResultMessage | undefined;
    try {
      for await (const message of query({ prompt: req.prompt, options })) {
        const text = assistantText(message);
        if (text !== '') {
          transcriptText += text;
          tee(text);
        }
        if (message.type === 'result') {
          result = message;
        }
      }
    } catch (err) {
      if (req.signal.aborted) {
        return this.failed(transcriptText, abortKind(req.signal), TIMEOUT_RC, result);
      }
      // Mirror a crashed CLI run (adw/_phases.py:482-516): keep the captured
      // output, report a nonzero rc, and let the invoker parse/nudge/fail.
      tee(`\n[claude runner error] ${String(err)}\n`);
      return this.failed(transcriptText, 'none', 1, result);
    } finally {
      req.signal.removeEventListener('abort', forwardAbort);
    }

    if (req.signal.aborted) {
      return this.failed(transcriptText, abortKind(req.signal), TIMEOUT_RC, result);
    }
    if (result === undefined) {
      tee('\n[claude runner error] stream ended without a result message\n');
      return this.failed(transcriptText, 'none', 1, undefined);
    }

    if (result.subtype === 'success') {
      if (transcriptText === '' && result.result !== '') {
        transcriptText = result.result;
        tee(result.result);
      }
      return {
        ok: !result.is_error,
        structured: asStructured(result.structured_output),
        transcriptText,
        usage: usageOf(result),
        rc: result.is_error ? 1 : 0,
        signal: 'none',
        sessionId: result.session_id,
      };
    }
    // error_max_budget_usd is the native cost cap → fail fast, no nudge;
    // every other error subtype (error_during_execution, error_max_turns,
    // error_max_structured_output_retries) stays 'none' so the invoker's
    // single nudge-retry applies exactly as to a failed CLI run.
    return {
      ok: false,
      structured: null,
      transcriptText,
      usage: usageOf(result),
      rc: 1,
      signal: result.subtype === 'error_max_budget_usd' ? 'budget' : 'none',
      sessionId: result.session_id,
    };
  }

  private failed(
    transcriptText: string,
    signal: PhaseResult['signal'],
    rc: number,
    result: SDKResultMessage | undefined,
  ): PhaseResult {
    return {
      ok: false,
      structured: null,
      transcriptText,
      usage: result !== undefined ? usageOf(result) : {},
      rc,
      signal,
      ...(result !== undefined ? { sessionId: result.session_id } : {}),
    };
  }
}

export function createRunner(): AgentRunner {
  return new ClaudeRunner();
}
