/**
 * Orchestrator-owned git/GitHub operations, ported from adw/_git.py.
 *
 * Under the phased model the coding agent never touches git/gh; the TS
 * control plane performs all branch/commit/push/PR/CI-watch/merge work here,
 * in the parent process whose environment may legitimately hold GH_TOKEN
 * (PLAN.md Section 3.3). No runner is granted git/gh tools, and none receives
 * GH_TOKEN in phased mode, so any git/gh the agent's shell could still invoke
 * fails closed.
 *
 * Every mutating operation honours dryRun by printing the command instead of
 * running it.
 */

import { capture, ghJson, note } from './exec.js';

/** Mirrors the Python (ok, error) tuples. */
export interface GitResult {
  ok: boolean;
  error: string | null;
}

export interface FailingJob {
  name: string;
  logExcerpt: string;
}

export type CiState = 'success' | 'failure' | 'pending' | 'none' | 'unknown';

export interface CiStatus {
  state: CiState;
  failingJobs: FailingJob[];
}

// Treat these PR-check conclusions/states as red (adw/_git.py:19-21).
const FAIL_CONCLUSIONS = new Set(['FAILURE', 'CANCELLED', 'TIMED_OUT', 'ACTION_REQUIRED', 'STARTUP_FAILURE']);
const FAIL_STATES = new Set(['FAILURE', 'ERROR']);
const PENDING_STATES = new Set(['PENDING', 'EXPECTED']);

/** Print a command under dry-run and return a success result; else null. */
function emit(cmd: readonly string[], dryRun: boolean): GitResult | null {
  if (dryRun) {
    console.log(`[dry-run] ${cmd.join(' ')}`);
    return { ok: true, error: null };
  }
  note(cmd.join(' '));
  return null;
}

/** Return the current git branch name (empty string if undeterminable). */
export function currentBranch(): string {
  return capture(['git', 'rev-parse', '--abbrev-ref', 'HEAD']).stdout.trim();
}

/** Fetch origin and switch to `branch`, creating it from origin/<base>. */
export function createOrCheckoutBranch(branch: string, base: string, dryRun = false): GitResult {
  if (dryRun) {
    console.log('[dry-run] git fetch origin --quiet');
    console.log(`[dry-run] git switch -c ${branch} origin/${base}`);
    return { ok: true, error: null };
  }

  capture(['git', 'fetch', 'origin', '--quiet']); // best effort; offline is tolerable
  const existsLocally =
    capture(['git', 'show-ref', '--verify', '--quiet', `refs/heads/${branch}`]).returncode === 0;
  const cmd = existsLocally
    ? ['git', 'switch', branch]
    : ['git', 'switch', '-c', branch, `origin/${base}`];

  note(cmd.join(' '));
  const result = capture(cmd);
  if (result.returncode !== 0) {
    return { ok: false, error: result.stderr.trim() || 'git switch failed' };
  }
  return { ok: true, error: null };
}

/** Stage all changes and commit `message`; a clean tree is a no-op success. */
export function commitAll(message: string, dryRun = false): GitResult {
  if (!dryRun && !capture(['git', 'status', '--porcelain']).stdout.trim()) {
    return { ok: true, error: null }; // nothing to commit
  }

  for (const cmd of [
    ['git', 'add', '-A'],
    ['git', 'commit', '-m', message],
  ]) {
    const emitted = emit(cmd, dryRun);
    if (emitted !== null) {
      continue;
    }
    const result = capture(cmd);
    if (result.returncode !== 0) {
      return { ok: false, error: result.stderr.trim() || 'git commit failed' };
    }
  }
  return { ok: true, error: null };
}

/** Push `branch` to origin, setting upstream. */
export function push(branch: string, dryRun = false): GitResult {
  const cmd = ['git', 'push', '-u', 'origin', branch];
  const emitted = emit(cmd, dryRun);
  if (emitted !== null) {
    return emitted;
  }
  const result = capture(cmd);
  if (result.returncode !== 0) {
    return { ok: false, error: result.stderr.trim() || 'git push failed' };
  }
  return { ok: true, error: null };
}

/** Switch back to `base` and rebase-pull it. */
export function pullRebase(base: string, dryRun = false): GitResult {
  for (const cmd of [
    ['git', 'switch', base],
    ['git', 'pull', '--rebase', 'origin', base],
  ]) {
    const emitted = emit(cmd, dryRun);
    if (emitted !== null) {
      continue;
    }
    const result = capture(cmd);
    if (result.returncode !== 0) {
      return { ok: false, error: result.stderr.trim() || 'git pull --rebase failed' };
    }
  }
  return { ok: true, error: null };
}

/** Return the URL of an existing open PR for `branch`, or null. */
export function prForBranch(branch: string, ghBin: string, repo: string): string | null {
  const args = [ghBin, 'pr', 'list', '--head', branch, '--json', 'url', '--state', 'open'];
  if (repo) {
    args.push('--repo', repo);
  }
  const prs = ghJson(args);
  if (Array.isArray(prs) && prs.length > 0) {
    const url = (prs[0] as Record<string, unknown>)['url'];
    return typeof url === 'string' ? url : null;
  }
  return null;
}

export interface CreatePrResult {
  number: number | null;
  url: string | null;
  error: string | null;
}

/** Open a PR for `branch`; return its number/url or an error. */
export function createPr(
  branch: string,
  title: string,
  body: string,
  base: string,
  ghBin: string,
  repo: string,
  dryRun = false,
): CreatePrResult {
  const args = [ghBin, 'pr', 'create', '--base', base, '--head', branch, '--title', title, '--body', body];
  if (repo) {
    args.push('--repo', repo);
  }
  if (dryRun) {
    console.log(`[dry-run] ${args.join(' ')}`);
    return { number: null, url: null, error: null };
  }
  note(`${args.slice(0, 6).join(' ')} …`);
  const result = capture(args);
  if (result.returncode !== 0) {
    return { number: null, url: null, error: result.stderr.trim() || 'gh pr create failed' };
  }
  const out = result.stdout.trim();
  const lines = out ? out.split('\n') : [];
  const url = lines.length > 0 ? (lines[lines.length - 1] ?? '') : '';
  return { number: prNumberFromUrl(url), url: url || null, error: null };
}

/**
 * Return {state, failingJobs} for a PR's checks (adw/_git.py:142-180).
 *
 * `none` means the query succeeded but the PR has no checks (yet), distinct
 * from `unknown` (the gh query itself failed / was unparseable); callers
 * settle on `none` before concluding there is nothing to gate on.
 * logExcerpt stays empty — fetching per-job logs is out of scope and would
 * risk leaking secrets.
 */
export function ciStatus(pr: number | string, ghBin: string, repo: string): CiStatus {
  const args = [ghBin, 'pr', 'view', String(pr), '--json', 'statusCheckRollup'];
  if (repo) {
    args.push('--repo', repo);
  }
  const data = ghJson(args);
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return { state: 'unknown', failingJobs: [] };
  }

  const rollup = (data as Record<string, unknown>)['statusCheckRollup'];
  if (!Array.isArray(rollup) || rollup.length === 0) {
    return { state: 'none', failingJobs: [] };
  }

  const failing: FailingJob[] = [];
  let pending = false;
  for (const entry of rollup) {
    const check = (typeof entry === 'object' && entry !== null ? entry : {}) as Record<string, unknown>;
    const name = String(check['name'] || check['context'] || 'check');
    const status = String(check['status'] ?? '').toUpperCase(); // CheckRun: QUEUED/IN_PROGRESS/COMPLETED
    const conclusion = String(check['conclusion'] ?? '').toUpperCase(); // CheckRun
    const state = String(check['state'] ?? '').toUpperCase(); // StatusContext
    if (FAIL_CONCLUSIONS.has(conclusion) || FAIL_STATES.has(state)) {
      failing.push({ name, logExcerpt: '' });
    } else if ((status && status !== 'COMPLETED') || PENDING_STATES.has(state)) {
      pending = true;
    }
  }

  if (failing.length > 0) {
    return { state: 'failure', failingJobs: failing };
  }
  if (pending) {
    return { state: 'pending', failingJobs: [] };
  }
  return { state: 'success', failingJobs: [] };
}

/** Squash-merge `pr` and delete its branch. */
export function squashMerge(pr: number | string, ghBin: string, repo: string, dryRun = false): GitResult {
  const args = [ghBin, 'pr', 'merge', String(pr), '--squash', '--delete-branch'];
  if (repo) {
    args.push('--repo', repo);
  }
  const emitted = emit(args, dryRun);
  if (emitted !== null) {
    return emitted;
  }
  const result = capture(args);
  if (result.returncode !== 0) {
    return { ok: false, error: result.stderr.trim() || 'gh pr merge failed' };
  }
  return { ok: true, error: null };
}

/** Extract the trailing PR number from a GitHub PR URL. */
export function prNumberFromUrl(url: string): number | null {
  if (!url) {
    return null;
  }
  const parts = url.replace(/\/+$/, '').split('/');
  const tail = parts[parts.length - 1] ?? '';
  return /^\d+$/.test(tail) ? Number.parseInt(tail, 10) : null;
}
