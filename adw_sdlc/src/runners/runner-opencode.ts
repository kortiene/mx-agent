/**
 * Runner #3: `opencode` via the `@opencode-ai/sdk` v2 client over a
 * SELF-SPAWNED `opencode serve` (PLAN.md roadmap step 8, Sections 4.3-3
 * and 5).
 *
 * The secret boundary is the orchestrator-owned spawn: the server child gets
 * exactly the `safeSubprocessEnv()` allowlist (plus OPENCODE_CONFIG_CONTENT,
 * which this adapter authors itself), and every tool the agent runs is a
 * grandchild of that clean-env server. The SDK's own `createOpencodeServer`
 * is NEVER used — it hardcodes a full parent-process-env spread onto the
 * child (verified on the installed 1.17.3 `dist/v2/server.js`), which is
 * exactly the leak D5 exists to prevent (enforced by
 * scripts/check-adw-sdlc-env.sh and the spawn-env tests).
 *
 * Step-8 [VERIFY] resolutions (installed 1.17.3 + live gate, see PLAN.md):
 * - Native schema: the v2 prompt route (`POST /session/{id}/message`, the
 *   `/v2/client` subpath export) accepts `format:{type:'json_schema',schema,
 *   retryCount}` and returns the parsed object on `info.structured`
 *   (`AssistantMessage.structured`), with `StructuredOutputError` on
 *   exhaustion surfacing via `info.error` → caps.nativeSchema:true.
 *   Mechanically the server exposes a `StructuredOutput` tool whose
 *   parameters ARE the schema; the model calls it, the server validates.
 * - Readiness banner: `opencode server listening on <url>` on stdout —
 *   the same banner the SDK's own server wrapper scrapes. `--port 0` does
 *   NOT bind ephemerally (it falls back to the default 4096, observed
 *   live), so the adapter picks a random high port and retries on a
 *   failed bind instead.
 * - Directory: the generated v2 client sends `directory` as an explicit
 *   query parameter on the prompt/create POSTs (dist/v2/gen/sdk.gen.js
 *   buildClientParams), so per-request cwd routing does not depend on the
 *   GET/HEAD-only header-rewrite interceptor.
 * - Config injection: the server reads OPENCODE_CONFIG_CONTENT (JSON) from
 *   its environment — the same channel the SDK wrapper uses — so the
 *   permission ruleset rides the spawn env, no config file in the worktree.
 *
 * Server lifecycle: PLAN.md sketched `start()` as the spawn point, but
 * `createRunner()` (the registry contract) takes no options — the allowlist
 * env and worktree only arrive with the first PhaseRequest. The server
 * therefore starts lazily on first runPhase (keyed to that request's
 * env/cwd; one server per run, sessions per phase), `start()` stays a
 * documented no-op for interface parity, and `stop()` is the load-bearing
 * teardown seam the orchestrator calls in a finally.
 */

import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { accessSync, appendFileSync, constants, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, join } from 'node:path';

import { createOpencodeClient } from '@opencode-ai/sdk/v2/client';
import type {
  AssistantMessage,
  OpencodeClient,
  Part,
} from '@opencode-ai/sdk/v2/client';

import type {
  AgentRunner,
  PhaseRequest,
  PhaseResult,
  PhaseUsage,
  RunnerCaps,
} from '../invoker.js';
import { abortKind, TIMEOUT_RC } from './shared.js';

/**
 * PLAN.md Section 5, opencode column. nativeSchema:true is gated on the
 * step-8 [VERIFY] (resolved — see the module header); permission control is
 * config allow/deny rules, not a per-call veto (perToolHook false); cost is
 * native (`AssistantMessage.cost`); no native budget gate.
 */
export const OPENCODE_CAPS: RunnerCaps = {
  nativeSchema: true,
  perToolHook: false,
  envIsolation: 'subprocess-allowlist',
  costUsd: true,
  nativeBudget: false,
  resume: true,
};

/**
 * Best-effort tool-permission half of the D5 boundary (PLAN.md Section 4.2):
 * everything allowed except bash git/gh (the orchestrator owns all git/gh,
 * Section 3.3 — mirrors the claude adapter's denyGitGh veto and the
 * PHASE_PREAMBLE_SHARED contract). NEVER 'ask' — there is no interactive
 * approver headless, so an 'ask' would hang the phase. The load-bearing
 * control stays GH_TOKEN's absence from the spawn env.
 */
export const OPENCODE_PERMISSION = {
  '*': 'allow',
  bash: {
    'git *': 'deny',
    'gh *': 'deny',
    '*': 'allow',
  },
} as const;

/** How long to wait for the readiness banner before failing the phase. */
export const SERVER_START_TIMEOUT_MS = 30_000;

/**
 * Bind attempts before giving up. `--port 0` is NOT an ephemeral bind
 * (verified live: it falls back to the default 4096), so the adapter draws
 * random high ports and retries when the server exits before its banner —
 * the observable symptom of a port collision.
 */
export const SERVER_BIND_ATTEMPTS = 3;

/** IANA dynamic/private port range. */
const PORT_RANGE_START = 49152;
const PORT_RANGE_SIZE = 16384;

function randomPort(): number {
  return PORT_RANGE_START + Math.floor(Math.random() * PORT_RANGE_SIZE);
}

/** The stdout line `opencode serve` prints when ready (verified 1.17.3). */
const READY_BANNER = 'opencode server listening';
const READY_URL = /on\s+(https?:\/\/\S+)/;

/**
 * Resolve the opencode binary like the claude adapter resolves its CLI
 * (adw/_exec.py:201-213 ported): OPENCODE_BIN override, then PATH, then the
 * documented install location. Resolution reads the ALLOWLIST env (the same
 * env the child gets), never process.env. Unlike codex there is no vendored
 * lockstep binary to fall back to — the SDK talks HTTP to whatever server
 * version answers — so a missing binary fails the phase (crashed-CLI parity).
 */
export function resolveOpencodeBin(env: Record<string, string | undefined>): string | undefined {
  const override = env['OPENCODE_BIN'];
  if (override) {
    return override;
  }
  for (const dir of (env['PATH'] ?? '').split(delimiter)) {
    if (dir && isExecutableFile(join(dir, 'opencode'))) {
      return join(dir, 'opencode');
    }
  }
  const home = env['HOME'] ?? homedir();
  const candidate = join(home, '.opencode/bin/opencode');
  return isExecutableFile(candidate) ? candidate : undefined;
}

function isExecutableFile(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/** Split the `provider/model` routing string (models.ts opencode tier ids). */
export function splitModel(model: string): { providerID: string; modelID: string } {
  const slash = model.indexOf('/');
  if (slash <= 0 || slash === model.length - 1) {
    // No provider prefix: hand the raw id to opencode's default provider
    // resolution rather than guessing one here.
    return { providerID: '', modelID: model };
  }
  return { providerID: model.slice(0, slash), modelID: model.slice(slash + 1) };
}

/**
 * opencode reports provider-shaped token counts on the assistant message;
 * `tokens.input` excludes cache reads for the Anthropic-style providers the
 * tier table routes to, matching PhaseUsage's disjoint convention. Counts
 * cross an HTTP boundary from an unpinned server version, so each field is
 * finite-checked — a drifted field degrades to undefined instead of
 * NaN-poisoning the run totals (step-7 lesson).
 */
function usageOf(info: AssistantMessage): PhaseUsage {
  const count = (value: unknown): number | undefined =>
    typeof value === 'number' && Number.isFinite(value) ? value : undefined;
  const tokens = info.tokens as Partial<AssistantMessage['tokens']> | undefined;

  const usage: PhaseUsage = {};
  const input = count(tokens?.input);
  const output = count(tokens?.output);
  const reasoning = count(tokens?.reasoning);
  const cached = count(tokens?.cache?.read);
  if (input !== undefined) usage.inputTokens = input;
  if (output !== undefined) usage.outputTokens = output;
  if (cached !== undefined) usage.cachedInputTokens = cached;
  if (reasoning !== undefined) usage.reasoningTokens = reasoning;
  // Native dollars (caps.costUsd) — null (unpriceable, non-fatal) if the
  // server ever stops reporting it, mirroring pricing.ts's degraded mode.
  usage.costUsd = count(info.cost) ?? null;
  return usage;
}

function asStructured(value: unknown): Record<string, unknown> | null {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return null;
}

/**
 * Transcript accumulator: text parts stream into BOTH transcriptText and the
 * file (deduped by written length, so `message.part.delta`,
 * `message.part.updated`, and the final response parts can all replay the
 * same text without double-writing); tool/error notes go to the FILE only,
 * keeping transcriptText assistant-text-only so the invoker's
 * trailing-fenced-JSON fallback keeps parsing (codex/claude convention).
 */
class Transcript {
  text = '';
  private readonly written = new Map<string, number>();
  private readonly noted = new Set<string>();

  constructor(private readonly path: string) {
    writeFileSync(path, '', 'utf8');
  }

  note(text: string): void {
    if (text !== '') {
      appendFileSync(this.path, text, 'utf8');
    }
  }

  noteOnce(key: string, text: string): void {
    if (!this.noted.has(key)) {
      this.noted.add(key);
      this.note(text);
    }
  }

  delta(partId: string, delta: string): void {
    if (delta === '') {
      return;
    }
    this.written.set(partId, (this.written.get(partId) ?? 0) + delta.length);
    this.text += delta;
    this.note(delta);
  }

  /** Append the unseen tail of a part's full text (updated/final replay). */
  fullText(partId: string, full: string): void {
    const seen = this.written.get(partId) ?? 0;
    if (full.length > seen) {
      const tail = full.slice(seen);
      this.written.set(partId, full.length);
      this.text += tail;
      this.note(tail);
    }
  }

  /** Terminal newline per completed text part, for CLI-transcript parity. */
  endPart(): void {
    if (this.text !== '' && !this.text.endsWith('\n')) {
      this.text += '\n';
      this.note('\n');
    }
  }
}

/** File-only note for a tool part that reached a terminal state. */
function toolNote(part: Extract<Part, { type: 'tool' }>): string | null {
  const state = part.state;
  if (state.status === 'completed') {
    return `[tool ${part.tool} completed] ${state.title}\n`;
  }
  if (state.status === 'error') {
    return `[tool ${part.tool} error] ${state.error}\n`;
  }
  return null;
}

interface Server {
  proc: ChildProcess;
  client: OpencodeClient;
  url: string;
}

class OpencodeRunner implements AgentRunner {
  readonly id = 'opencode' as const;
  readonly caps = OPENCODE_CAPS;

  private server: Server | null = null;
  private starting: Promise<Server> | null = null;

  /**
   * Interface-parity no-op (D6): the server needs the request's env/cwd,
   * which the registry's createRunner() contract cannot provide, so the
   * spawn happens lazily on the first runPhase instead.
   */
  start(): Promise<void> {
    return Promise.resolve();
  }

  /** Kill the self-spawned server; the orchestrator calls this in a finally. */
  stop(): Promise<void> {
    this.starting = null;
    const server = this.server;
    this.server = null;
    if (server !== null && server.proc.exitCode === null && !server.proc.killed) {
      server.proc.kill('SIGTERM');
    }
    return Promise.resolve();
  }

  async runPhase(req: PhaseRequest): Promise<PhaseResult> {
    const transcript = new Transcript(req.transcriptPath);
    if (req.signal.aborted) {
      // Don't spawn a server for a phase that is already dead.
      return this.failed(transcript, abortKind(req.signal), TIMEOUT_RC, null);
    }

    let server: Server;
    try {
      server = await this.ensureServer(req);
    } catch (err) {
      // A server that never came up mirrors a crashed CLI run: failed
      // result, output kept, never an exception out of the seam.
      transcript.note(`[opencode runner error] ${String(err)}\n`);
      return this.failed(transcript, req.signal.aborted ? abortKind(req.signal) : 'none',
        req.signal.aborted ? TIMEOUT_RC : 1, null);
    }

    let sessionId: string | undefined;
    let info: AssistantMessage | undefined;
    let parts: Part[] = [];
    // The SSE tee is scoped to this phase; aborting it never cancels the
    // prompt itself.
    const events = new AbortController();
    try {
      const created = await server.client.session.create(
        { directory: req.cwd, title: `adw ${req.phase}` },
        { signal: req.signal },
      );
      if (created.error !== undefined || created.data === undefined) {
        transcript.note(`[opencode runner error] session.create failed: ${describe(created.error)}\n`);
        return this.failed(transcript, 'none', 1, null);
      }
      sessionId = created.data.id;

      void this.teeEvents(server.client, sessionId, transcript, events.signal);

      const res = await server.client.session.prompt(
        {
          sessionID: sessionId,
          directory: req.cwd,
          ...(splitModel(req.model).providerID !== ''
            ? { model: splitModel(req.model) }
            : {}),
          parts: [{ type: 'text', text: req.prompt }],
          ...(req.schema !== undefined
            ? {
                format: {
                  type: 'json_schema' as const,
                  schema: req.schema,
                  // One native retry; the invoker's single nudge stays the
                  // cross-runner fallback (PLAN.md Section 7).
                  retryCount: 1,
                },
              }
            : {}),
        },
        { signal: req.signal },
      );
      if (res.error !== undefined || res.data === undefined) {
        transcript.note(`[opencode runner error] prompt failed: ${describe(res.error)}\n`);
        return this.failed(transcript, 'none', 1, null, sessionId);
      }
      info = res.data.info;
      parts = res.data.parts;
    } catch (err) {
      if (req.signal.aborted) {
        // Best-effort server-side stop so an aborted phase stops burning
        // tokens; the orchestrator's stop() remains the hard teardown.
        if (sessionId !== undefined) {
          void server.client.session.abort({ sessionID: sessionId, directory: req.cwd }).catch(() => {});
        }
        return this.failed(transcript, abortKind(req.signal), TIMEOUT_RC, null, sessionId);
      }
      transcript.note(`\n[opencode runner error] ${String(err)}\n`);
      return this.failed(transcript, 'none', 1, null, sessionId);
    } finally {
      events.abort();
    }

    // Replay the authoritative final parts through the dedup tracker: catches
    // anything the SSE tee missed (or everything, if events never flowed).
    for (const part of parts) {
      if (part.type === 'text') {
        transcript.fullText(part.id, part.text);
        transcript.endPart();
      } else if (part.type === 'tool') {
        const note = toolNote(part);
        if (note !== null) {
          transcript.noteOnce(part.id, note);
        }
      }
    }

    if (req.signal.aborted) {
      // Late abort after a completed prompt: parse-first parity — keep the
      // structured payload, still report the abort (the invoker owns policy).
      return this.failed(transcript, abortKind(req.signal), TIMEOUT_RC, info, sessionId);
    }
    if (info.error !== undefined) {
      // StructuredOutputError, provider/auth errors, aborts observed
      // server-side: opencode has no native budget cap (caps.nativeBudget
      // false), so every message error stays signal 'none' and the invoker's
      // single nudge applies exactly as to a failed CLI run. File only.
      transcript.note(`\n[opencode ${info.error.name}] ${describe(info.error.data)}\n`);
      return {
        ok: false,
        structured: asStructured(info.structured),
        transcriptText: transcript.text,
        usage: usageOf(info),
        rc: 1,
        signal: 'none',
        ...(sessionId !== undefined ? { sessionId } : {}),
      };
    }

    return {
      ok: true,
      structured: asStructured(info.structured),
      transcriptText: transcript.text,
      usage: usageOf(info),
      rc: 0,
      signal: 'none',
      ...(sessionId !== undefined ? { sessionId } : {}),
    };
  }

  /** One server per run, keyed to the first request's env/cwd; concurrent callers share the same spawn. */
  private ensureServer(req: PhaseRequest): Promise<Server> {
    if (this.server !== null) {
      return Promise.resolve(this.server);
    }
    if (this.starting === null) {
      const starting = this.spawnServer(req).then((server) => {
        if (this.starting !== starting) {
          // stop() ran while the server was starting; don't resurrect it.
          if (server.proc.exitCode === null && !server.proc.killed) {
            server.proc.kill('SIGTERM');
          }
          throw new Error('opencode runner stopped during server start');
        }
        this.server = server;
        return server;
      }).catch((err: unknown) => {
        if (this.starting === starting) {
          this.starting = null;
        }
        throw err;
      });
      this.starting = starting;
    }
    return this.starting;
  }

  private async spawnServer(req: PhaseRequest): Promise<Server> {
    const bin = resolveOpencodeBin(req.env);
    if (bin === undefined) {
      throw new Error('opencode binary not found (set OPENCODE_BIN or add opencode to PATH)');
    }
    // A server that exits before its banner is the observable symptom of a
    // port collision (EADDRINUSE detail varies by release) — redraw and
    // retry; spawn failures and banner timeouts are not bind problems and
    // fail immediately.
    let lastErr: unknown;
    for (let attempt = 0; attempt < SERVER_BIND_ATTEMPTS; attempt += 1) {
      try {
        return await this.spawnServerOnce(req, bin, randomPort());
      } catch (err) {
        lastErr = err;
        if (!(err instanceof Error && (err as { retryable?: boolean }).retryable === true)) {
          throw err;
        }
      }
    }
    throw lastErr;
  }

  private spawnServerOnce(req: PhaseRequest, bin: string, port: number): Promise<Server> {
    const proc = spawn(bin, ['serve', '--hostname', '127.0.0.1', '--port', String(port)], {
      cwd: req.cwd,
      // The allowlist verbatim, plus the permission config this adapter
      // authors; grandchildren (the agent's tools) inherit this clean env.
      env: { ...req.env, OPENCODE_CONFIG_CONTENT: JSON.stringify({ permission: OPENCODE_PERMISSION }) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    return new Promise<Server>((resolve, reject) => {
      let output = '';
      let settled = false;
      const fail = (message: string, retryable = false): void => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          if (proc.exitCode === null && !proc.killed) {
            proc.kill('SIGTERM');
          }
          const err = new Error(message) as Error & { retryable: boolean };
          err.retryable = retryable;
          reject(err);
        }
      };
      const timer = setTimeout(() => {
        fail(`opencode serve produced no readiness banner within ${SERVER_START_TIMEOUT_MS}ms: ${output.trim()}`);
      }, SERVER_START_TIMEOUT_MS);

      const onData = (chunk: Buffer | string): void => {
        if (settled) {
          return;
        }
        output += chunk.toString();
        for (const line of output.split('\n')) {
          if (line.includes(READY_BANNER)) {
            const match = READY_URL.exec(line);
            if (match === null) {
              fail(`could not parse the server url from: ${line.trim()}`);
              return;
            }
            settled = true;
            clearTimeout(timer);
            const url = match[1]!;
            resolve({ proc, url, client: createOpencodeClient({ baseUrl: url }) });
            return;
          }
        }
      };
      proc.stdout?.on('data', onData);
      // Some releases log the banner via the logger (stderr); scrape both.
      proc.stderr?.on('data', onData);
      proc.on('error', (err) => fail(`failed to spawn opencode: ${String(err)}`));
      proc.on('exit', (code) =>
        fail(`opencode serve exited with code ${String(code)} before ready: ${output.trim()}`, true),
      );
    });
  }

  /**
   * Background SSE tee: stream this session's assistant text deltas/updates
   * and tool completions to the transcript while the prompt runs.
   * Best-effort by design — the final-parts replay in runPhase is the
   * authoritative source, so SSE drift can only delay text, never lose or
   * duplicate it. Parts are teed only once their message is known to be an
   * assistant message (`message.updated` precedes the part stream): the SSE
   * bus also replays the USER message's text parts (observed live), which
   * must not be echoed into an assistant-text-only transcript.
   */
  private async teeEvents(
    client: OpencodeClient,
    sessionId: string,
    transcript: Transcript,
    signal: AbortSignal,
  ): Promise<void> {
    const assistantMessages = new Set<string>();
    const isAssistantPart = (part: Part): boolean =>
      part.sessionID === sessionId && assistantMessages.has(part.messageID);
    try {
      const result = await client.event.subscribe(undefined, { signal });
      for await (const event of result.stream) {
        const e = event as { type?: string; properties?: Record<string, unknown> };
        if (e.type === 'message.updated') {
          const p = e.properties as { sessionID: string; info: { id: string; role: string } };
          if (p.sessionID === sessionId && p.info.role === 'assistant') {
            assistantMessages.add(p.info.id);
          }
        } else if (e.type === 'message.part.delta') {
          const p = e.properties as {
            sessionID: string;
            messageID: string;
            partID: string;
            field: string;
            delta: string;
          };
          if (p.sessionID === sessionId && assistantMessages.has(p.messageID) && p.field === 'text') {
            transcript.delta(p.partID, p.delta);
          }
        } else if (e.type === 'message.part.updated') {
          const p = e.properties as { part: Part };
          if (!isAssistantPart(p.part)) {
            continue;
          }
          if (p.part.type === 'text') {
            transcript.fullText(p.part.id, p.part.text);
          } else if (p.part.type === 'tool') {
            const note = toolNote(p.part);
            if (note !== null) {
              transcript.noteOnce(p.part.id, note);
            }
          }
        } else if (e.type === 'session.error') {
          const p = e.properties as { sessionID?: string; error?: { name?: string } };
          if (p.sessionID === sessionId) {
            transcript.note(`[opencode session.error] ${p.error?.name ?? 'unknown'}\n`);
          }
        }
      }
    } catch {
      // Aborted at phase end, or SSE hiccup — the final-parts replay covers it.
    }
  }

  private failed(
    transcript: Transcript,
    signal: PhaseResult['signal'],
    rc: number,
    info: AssistantMessage | null | undefined,
    sessionId?: string,
  ): PhaseResult {
    return {
      ok: false,
      // A completed assistant message that arrived before a late abort still
      // carries the structured payload through (parse-first parity with the
      // claude/codex adapters; the invoker owns the policy).
      structured: info != null ? asStructured(info.structured) : null,
      transcriptText: transcript.text,
      usage: info != null ? usageOf(info) : {},
      rc,
      signal,
      ...(sessionId !== undefined ? { sessionId } : {}),
    };
  }
}

/** Render an error payload for a file-only transcript note. */
function describe(value: unknown): string {
  if (value === undefined || value === null) {
    return 'no response';
  }
  if (typeof value === 'object') {
    const message = (value as { message?: unknown }).message;
    if (typeof message === 'string') {
      return message;
    }
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

export function createRunner(): AgentRunner {
  return new OpencodeRunner();
}
