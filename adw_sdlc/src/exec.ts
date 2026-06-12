/**
 * Execution helpers ported from adw/_exec.py: subprocess capture, gh/git
 * queries, executable resolution, console notes, and the run-tagged GitHub
 * progress comments. The env allowlist lives in env.ts (PLAN.md layout);
 * everything else from _exec.py lands here.
 *
 * Commands run synchronously (spawnSync): the control plane is strictly
 * sequential, exactly like the Python pipeline's subprocess.run usage.
 */

import { spawnSync } from 'node:child_process';
import { accessSync, constants, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, join } from 'node:path';
import { createInterface } from 'node:readline';

/** Result shape mirroring Python's CompletedProcess slice we use. */
export interface Captured {
  returncode: number;
  stdout: string;
  stderr: string;
}

// --- console -----------------------------------------------------------------

/** Print a progress note to stderr (stdout carries command output). */
export function note(message: string): void {
  process.stderr.write(`>> ${message}\n`);
}

/** Whether confirmation prompts should be skipped (flag or MX_AGENT_YES=1). */
export function assumeYes(flag: boolean, env: Record<string, string | undefined> = process.env): boolean {
  return flag || env['MX_AGENT_YES'] === '1';
}

/** Write a prompt to stderr and read a yes/no answer from stdin. */
export function confirm(prompt: string): Promise<boolean> {
  process.stderr.write(prompt);
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin });
    rl.once('line', (line) => {
      rl.close();
      resolve(['y', 'yes'].includes(line.trim().toLowerCase()));
    });
    rl.once('close', () => resolve(false));
  });
}

// --- issue progress comments ---------------------------------------------------

/**
 * Tag stamped on every ADW-authored issue comment so any future trigger can
 * skip the tool's own comments and avoid feedback loops (adw/_exec.py:58).
 */
export const MX_ADW_BOT_TAG = '[MX-ADW]';

/**
 * Format a run-tagged progress line for a GitHub issue comment. Built only
 * from the run id, phase, and a caller-supplied fixed message — never runner
 * output, environment, or secrets (adw/_exec.py:61-68).
 */
export function formatProgress(adwId: string, phase: string, message: string): string {
  return `${MX_ADW_BOT_TAG} ${adwId}_${phase}: ${message}`;
}

/** Best-effort `gh issue comment` with a run-tagged body; never throws. */
export function postProgress(
  ghBin: string | null,
  issue: number | string,
  repo: string,
  adwId: string,
  phase: string,
  message: string,
): void {
  if (!ghBin) {
    return;
  }
  const args = [ghBin, 'issue', 'comment', String(issue), '--body', formatProgress(adwId, phase, message)];
  if (repo) {
    args.push('--repo', repo);
  }
  const result = capture(args);
  if (result.returncode !== 0) {
    note(`could not post progress comment for #${issue} (${phase})`);
  }
}

// --- subprocess ----------------------------------------------------------------

/**
 * Run a command capturing text stdout/stderr; never throws. A missing binary
 * (or other spawn error) maps to a synthetic exit code 127 with the error
 * text on stderr, so "command failed" and "command absent" are uniform
 * (adw/_exec.py:147-159).
 */
export function capture(cmd: readonly string[]): Captured {
  const [bin, ...args] = cmd;
  if (bin === undefined) {
    return { returncode: 127, stdout: '', stderr: 'empty command' };
  }
  const result = spawnSync(bin, args, { encoding: 'utf8' });
  if (result.error) {
    return { returncode: 127, stdout: result.stdout ?? '', stderr: String(result.error) };
  }
  return {
    returncode: result.status ?? 127,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

/** Run a command with inherited stdio; return its exit code. */
export function runInherit(cmd: readonly string[]): number {
  const [bin, ...args] = cmd;
  if (bin === undefined) {
    return 127;
  }
  const result = spawnSync(bin, args, { stdio: 'inherit' });
  return result.status ?? 127;
}

/** Run a `gh` command expected to emit JSON; return parsed data or null. */
export function ghJson(cmd: readonly string[]): unknown {
  const result = capture(cmd);
  if (result.returncode !== 0) {
    return null;
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    return null;
  }
}

// --- executable resolution -------------------------------------------------------

function which(name: string, env: Record<string, string | undefined>): string | null {
  for (const dir of (env['PATH'] ?? '').split(delimiter)) {
    if (!dir) {
      continue;
    }
    const candidate = join(dir, name);
    if (isExecutableFile(candidate)) {
      return candidate;
    }
  }
  return null;
}

function isExecutableFile(path: string): boolean {
  try {
    if (!statSync(path).isFile()) {
      return false;
    }
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Resolve an executable via an env override, $PATH, then fallbacks. */
function resolveBin(
  envVar: string,
  name: string,
  fallbacks: readonly string[],
  env: Record<string, string | undefined>,
): string | null {
  const override = env[envVar];
  if (override) {
    return override;
  }
  const found = which(name, env);
  if (found) {
    return found;
  }
  for (const candidate of fallbacks) {
    if (isExecutableFile(candidate)) {
      return candidate;
    }
  }
  return null;
}

/** Resolve the `gh` executable, or null if unavailable (adw/_exec.py:216-219). */
export function resolveGhBin(env: Record<string, string | undefined> = process.env): string | null {
  return resolveBin('GH_BIN', 'gh', [join(homedir(), '.local/bin/gh')], env);
}

// --- GitHub / git queries ----------------------------------------------------------

/** Return an issue's state via `gh`, or `UNKNOWN` if undeterminable. */
export function issueState(ghBin: string | null, issue: number, repo: string): string {
  if (!ghBin) {
    return 'UNKNOWN';
  }
  const args = [ghBin, 'issue', 'view', String(issue)];
  if (repo) {
    args.push('--repo', repo);
  }
  args.push('--json', 'state', '-q', '.state');
  const result = capture(args);
  if (result.returncode !== 0) {
    return 'UNKNOWN';
  }
  return result.stdout.trim() || 'UNKNOWN';
}

/** Best-effort `owner/repo` detection via `gh`, or empty string. */
export function detectRepo(ghBin: string | null): string {
  if (!ghBin) {
    return '';
  }
  const result = capture([ghBin, 'repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner']);
  return result.returncode === 0 ? result.stdout.trim() : '';
}

/** Return true when inside a git work tree with uncommitted changes. */
export function workingTreeDirty(): boolean {
  const inside = capture(['git', 'rev-parse', '--is-inside-work-tree']);
  if (inside.returncode !== 0) {
    return false;
  }
  return capture(['git', 'status', '--porcelain']).stdout.trim().length > 0;
}
