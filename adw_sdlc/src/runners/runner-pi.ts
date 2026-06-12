/**
 * Runner #4: `pi` via the `pi` CLI's `--mode json` event stream over an
 * orchestrator-owned subprocess (PLAN.md roadmap step 9, Sections 4.3-4
 * and 5).
 *
 * The secret boundary is the orchestrator-owned spawn: the CLI child gets
 * exactly the `safeSubprocessEnv()` allowlist, and every tool the agent runs
 * (bash, edit, write) is a grandchild of that clean env. The invocation uses
 * the same binary and flag mapping the Python pipeline drives today
 * (build_runner_command, adw/_runner.py:43-50), so the agentic behavior is
 * field-proven — with one deliberate upgrade: the phased Python caller runs
 * text mode (json_mode=False, adw/_phases.py:534) and scrapes the final
 * text, while this adapter always opts into `--mode json` to parse the
 * event stream natively (usage, native cost, stopReason, session id).
 *
 * Step-9 [VERIFY] resolutions (installed 0.79.1 dist, see PLAN.md):
 * - `--mode json` IS the cleaner stream: print mode subscribes to the
 *   AgentSession event bus and writes one JSON event per stdout line
 *   (dist/modes/print-mode.js), preceded by the session header
 *   ({type:'session', id, cwd, ...}). The stream carries assistant text
 *   deltas (`message_update`/`text_delta`), full messages with per-message
 *   `usage` incl. native dollars (`message_end` → usage.cost.total),
 *   stopReason/errorMessage, and tool events. Plain `-p` prints only the
 *   final text (no usage/cost/stopReason); `--mode rpc` is a long-lived
 *   bidirectional protocol for interactive clients — wrong shape for a
 *   single-shot phase.
 * - AuthStorage/agentDir vs the non-inheriting env: the CLI builds its
 *   AuthStorage from `getAgentDir()/auth.json`, where getAgentDir() reads
 *   PI_CODING_AGENT_DIR else $HOME/.pi/agent (dist/config.js:393-398);
 *   provider keys then resolve auth.json → env (ANTHROPIC_API_KEY /
 *   OPENAI_API_KEY, pi-ai dist/env-api-keys.js) → models.json fallback. So
 *   under the allowlist the child sees exactly the forwarded provider keys,
 *   and PI_CODING_AGENT_DIR / PI_CODING_AGENT_SESSION_DIR (allowlisted in
 *   env.ts) let callers point the HOME-reachable ~/.pi/agent surface at a
 *   scrubbed throwaway dir — the Section 4.4 mitigation, like CODEX_HOME.
 * - Driving the CLI (not the in-process SDK in a bespoke child) also keeps
 *   this module import-free: the npm package's engines floor (node
 *   >=22.19.0) makes the optionalDependency vanish on older Node installs,
 *   which a static SDK type-import would turn into a typecheck break. The
 *   pi runner therefore never raises RunnerNotInstalledError — a missing
 *   `pi` BINARY surfaces per-phase as a failed PhaseResult (crashed-CLI
 *   parity), exactly like a missing opencode server binary.
 *
 * Headless notes (verified on the installed 0.79.1):
 * - In `--mode json` the process exits 0 even when the final assistant
 *   message failed (the stopReason check in print-mode.js is text-mode
 *   only), so the adapter derives failure from the last assistant message's
 *   stopReason ('error'/'aborted') itself.
 * - Project trust resolves silently to UNTRUSTED headless (no UI, no
 *   --approve override → resolveProjectTrusted returns false), which only
 *   skips project-local .pi settings/extensions — the orchestrator inlines
 *   the full prompt, so nothing load-bearing is lost, and not executing
 *   workspace-supplied extensions is the safer default for D5.
 */

import { spawn } from 'node:child_process';
import { accessSync, appendFileSync, constants, statSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { createInterface } from 'node:readline';

import type {
  AgentRunner,
  PhaseRequest,
  PhaseResult,
  PhaseUsage,
  RunnerCaps,
} from '../invoker.js';
import { abortKind, TIMEOUT_RC } from './shared.js';

/**
 * PLAN.md Section 5, pi column. No native JSON-schema output (PromptOptions
 * has no responseFormat) → the invoker's fenced-JSON contract + single nudge
 * is pi's PRIMARY path; tool control is coarse (no per-call veto without an
 * extension); cost is native per assistant message (usage.cost.total).
 */
export const PI_CAPS: RunnerCaps = {
  nativeSchema: false,
  perToolHook: false,
  envIsolation: 'subprocess-allowlist',
  costUsd: true,
  nativeBudget: false,
  resume: true,
};

/**
 * Grace between the abort SIGTERM and a SIGKILL escalation. Print mode
 * installs a SIGTERM handler that disposes the session and exits 143
 * (dist/modes/print-mode.js); the escalation only exists so a wedged child
 * cannot hang runPhase forever.
 */
export const KILL_GRACE_MS = 10_000;

/**
 * Resolve the pi binary like the opencode adapter resolves its CLI
 * (adw/_exec.py:201-213 ported): PI_BIN override, then PATH. Resolution
 * reads the ALLOWLIST env (the same env the child gets), never process.env.
 * There is no vendored fallback binary — a missing binary fails the phase.
 */
export function resolvePiBin(env: Record<string, string | undefined>): string | undefined {
  const override = env['PI_BIN'];
  if (override) {
    return override;
  }
  for (const dir of (env['PATH'] ?? '').split(delimiter)) {
    if (dir && isExecutableFile(join(dir, 'pi'))) {
      return join(dir, 'pi');
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

/**
 * Map the request onto pi's print-mode invocation — the same flags, in the
 * same order, as the Python build_runner_command (adw/_runner.py:43-50),
 * with json_mode always on (the whole point of the TS adapter) and the
 * tier→effort hint riding --thinking (ReasoningEffort values are a strict
 * subset of pi's ThinkingLevel union, verified dist/cli/args.js).
 */
export function buildPiArgs(req: PhaseRequest): string[] {
  return [
    '-p',
    '--mode',
    'json',
    '--model',
    req.model,
    ...(req.reasoning !== undefined ? ['--thinking', req.reasoning] : []),
    req.prompt,
  ];
}

/**
 * One JSON-per-line event from the child's stdout: the session header
 * (dist/core/session-manager.d.ts SessionHeader) followed by every
 * AgentSessionEvent the print-mode subscription relays
 * (pi-agent-core dist/types.d.ts AgentEvent). Only the fields the adapter
 * consumes are modeled; everything else flows through untouched.
 */
interface PiEvent {
  type?: string;
  // SessionHeader
  id?: string;
  // message_start / message_end
  message?: PiMessage;
  // message_update
  assistantMessageEvent?: { type?: string; delta?: string };
}

interface PiMessage {
  role?: string;
  content?: Array<{ type?: string; text?: string }>;
  usage?: {
    input?: number;
    output?: number;
    cacheRead?: number;
    cacheWrite?: number;
    cost?: { total?: number };
  };
  stopReason?: string;
  errorMessage?: string;
}

/**
 * Transcript accumulator (opencode-adapter convention): assistant text
 * streams into BOTH transcriptText and the file; tool/error/stderr notes go
 * to the FILE only, keeping transcriptText assistant-text-only so the
 * invoker's trailing-fenced-JSON contract — pi's primary structured-output
 * path — keeps parsing.
 */
class Transcript {
  text = '';

  constructor(private readonly path: string) {
    writeFileSync(path, '', 'utf8');
  }

  note(text: string): void {
    if (text !== '') {
      appendFileSync(this.path, text, 'utf8');
    }
  }

  append(text: string): void {
    if (text !== '') {
      this.text += text;
      this.note(text);
    }
  }

  /** Terminal newline per completed assistant message, for CLI-transcript parity. */
  endMessage(): void {
    if (this.text !== '' && !this.text.endsWith('\n')) {
      this.append('\n');
    }
  }
}

const count = (value: unknown): number | undefined =>
  typeof value === 'number' && Number.isFinite(value) ? value : undefined;

/**
 * Per-run usage accumulator. pi reports usage per assistant message
 * (a turn holds several, one per tool round-trip); tokens are summed with
 * the same finite-checks as the opencode adapter — counts come from an
 * unpinned external binary, so a drifted field degrades to undefined/null
 * instead of NaN-poisoning the run totals (step-7 lesson). pi-ai's `input`
 * is provider-shaped and cache-disjoint for the Anthropic-style providers
 * the tier table routes to, matching PhaseUsage's convention; cacheWrite
 * has no PhaseUsage slot (its dollars are already inside cost.total).
 */
class UsageTotals {
  private input: number | undefined;
  private output: number | undefined;
  private cached: number | undefined;
  private cost: number | null | undefined;
  private seen = false;

  add(usage: PiMessage['usage']): void {
    this.seen = true;
    const accumulate = (
      current: number | undefined,
      value: number | undefined,
    ): number | undefined =>
      value === undefined ? current : (current ?? 0) + value;
    this.input = accumulate(this.input, count(usage?.input));
    this.output = accumulate(this.output, count(usage?.output));
    this.cached = accumulate(this.cached, count(usage?.cacheRead));
    // Native dollars (caps.costUsd). A single unpriceable message makes the
    // phase total unknown — sticky null, never a false partial sum
    // (mirroring run-phase.ts mergeUsage).
    const total = count(usage?.cost?.total);
    if (total === undefined || this.cost === null) {
      this.cost = null;
    } else {
      this.cost = (this.cost ?? 0) + total;
    }
  }

  toPhaseUsage(): PhaseUsage {
    if (!this.seen) {
      return {};
    }
    const usage: PhaseUsage = {};
    if (this.input !== undefined) usage.inputTokens = this.input;
    if (this.output !== undefined) usage.outputTokens = this.output;
    if (this.cached !== undefined) usage.cachedInputTokens = this.cached;
    usage.costUsd = this.cost ?? null;
    return usage;
  }
}

class PiRunner implements AgentRunner {
  readonly id = 'pi' as const;
  readonly caps = PI_CAPS;

  async runPhase(req: PhaseRequest): Promise<PhaseResult> {
    const transcript = new Transcript(req.transcriptPath);
    const usage = new UsageTotals();

    if (req.signal.aborted) {
      // Don't spawn a child for a phase that is already dead.
      return failed(transcript, usage, abortKind(req.signal), TIMEOUT_RC);
    }

    const bin = resolvePiBin(req.env);
    if (bin === undefined) {
      transcript.note('[pi runner error] pi binary not found (set PI_BIN or add pi to PATH)\n');
      return failed(transcript, usage, 'none', 1);
    }

    const child = spawn(bin, buildPiArgs(req), {
      cwd: req.cwd,
      // The allowlist verbatim — the load-bearing D5 boundary; grandchildren
      // (the agent's bash/edit tools) inherit this clean env.
      env: req.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let sessionId: string | undefined;
    // Streamed-delta length of the in-flight assistant message, so the
    // authoritative full text on its message_end can append only the unseen
    // tail (deltas and finals replay the same text, opencode convention).
    let written = 0;
    let lastStop: string | undefined;
    let lastError: string | undefined;

    const onEvent = (event: PiEvent): void => {
      if (event.type === 'session' && typeof event.id === 'string') {
        sessionId = event.id;
      } else if (event.type === 'message_start') {
        if (event.message?.role === 'assistant') {
          written = 0;
        }
      } else if (event.type === 'message_update') {
        const delta = event.assistantMessageEvent;
        if (delta?.type === 'text_delta' && typeof delta.delta === 'string') {
          transcript.append(delta.delta);
          written += delta.delta.length;
        }
      } else if (event.type === 'message_end') {
        const message = event.message;
        if (message?.role !== 'assistant') {
          return;
        }
        const full = (message.content ?? [])
          .filter((block) => block.type === 'text' && typeof block.text === 'string')
          .map((block) => block.text)
          .join('');
        if (full.length > written) {
          transcript.append(full.slice(written));
        }
        written = 0;
        transcript.endMessage();
        usage.add(message.usage);
        lastStop = message.stopReason;
        lastError = message.errorMessage;
      } else if (event.type === 'tool_execution_end') {
        const e = event as { toolName?: string; isError?: boolean };
        transcript.note(`[tool ${e.toolName ?? 'unknown'} ${e.isError === true ? 'error' : 'completed'}]\n`);
      }
    };

    const lines = createInterface({ input: child.stdout! });
    lines.on('line', (line) => {
      if (line.trim() === '') {
        return;
      }
      let event: PiEvent;
      try {
        event = JSON.parse(line) as PiEvent;
      } catch {
        // Stray non-JSON stdout (warnings, deprecation notices): keep it for
        // the post-mortem, never let it kill the phase.
        transcript.note(`[pi stdout] ${line}\n`);
        return;
      }
      onEvent(event);
    });
    child.stderr!.on('data', (chunk: Buffer | string) => {
      transcript.note(`[pi stderr] ${chunk.toString()}`);
    });

    // Abort = kill the child (the print-mode SIGTERM handler disposes and
    // exits 143), with a SIGKILL escalation so a wedged child cannot hang
    // the phase; the unref'd timer never holds the event loop open.
    let killTimer: NodeJS.Timeout | undefined;
    const onAbort = (): void => {
      if (child.exitCode === null && !child.killed) {
        child.kill('SIGTERM');
        killTimer = setTimeout(() => {
          if (child.exitCode === null) {
            child.kill('SIGKILL');
          }
        }, KILL_GRACE_MS);
        killTimer.unref?.();
      }
    };
    req.signal.addEventListener('abort', onAbort, { once: true });

    const rc = await new Promise<number>((resolve) => {
      let spawnFailed = false;
      child.on('error', (err) => {
        // ENOENT and friends: spawn never produced a process. Mirrors a
        // crashed CLI run — failed result, never an exception out of the seam.
        spawnFailed = true;
        transcript.note(`[pi runner error] failed to spawn pi: ${String(err)}\n`);
        resolve(1);
      });
      // 'close' (not 'exit') so stdout is fully drained before results are read.
      child.on('close', (code) => {
        if (!spawnFailed) {
          resolve(code ?? 1);
        }
      });
    });
    req.signal.removeEventListener('abort', onAbort);
    if (killTimer !== undefined) {
      clearTimeout(killTimer);
    }
    lines.close();

    if (req.signal.aborted) {
      // Late abort after completed output: transcriptText keeps whatever
      // arrived (parse-first parity — the invoker owns the policy).
      return failed(transcript, usage, abortKind(req.signal), TIMEOUT_RC, sessionId);
    }
    if (rc !== 0) {
      return failed(transcript, usage, 'none', rc, sessionId);
    }
    if (lastStop === 'error' || lastStop === 'aborted') {
      // --mode json exits 0 even when the assistant turn failed (the
      // stopReason check in print-mode.js is text-mode only); pi has no
      // native budget cap (caps.nativeBudget false), so every turn error
      // stays signal 'none' and the invoker's single nudge applies exactly
      // as to a failed CLI run. File only.
      transcript.note(`\n[pi ${lastStop}] ${lastError ?? 'no error message'}\n`);
      return failed(transcript, usage, 'none', 1, sessionId);
    }

    return {
      ok: true,
      structured: null, // no native schema; the invoker parses the fenced JSON
      transcriptText: transcript.text,
      usage: usage.toPhaseUsage(),
      rc: 0,
      signal: 'none',
      ...(sessionId !== undefined ? { sessionId } : {}),
    };
  }
}

function failed(
  transcript: Transcript,
  usage: UsageTotals,
  signal: PhaseResult['signal'],
  rc: number,
  sessionId?: string,
): PhaseResult {
  return {
    ok: false,
    structured: null,
    transcriptText: transcript.text,
    usage: usage.toPhaseUsage(),
    rc,
    signal,
    ...(sessionId !== undefined ? { sessionId } : {}),
  };
}

export function createRunner(): AgentRunner {
  return new PiRunner();
}
