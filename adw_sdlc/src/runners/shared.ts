/**
 * Helpers shared by the runner adapters (not part of the AgentRunner seam).
 */

/**
 * rc reported when the parent's signal killed the run. The TS invoker keys
 * off PhaseResult.signal, never this number; 124 is kept only so transcripts
 * read like today's `timeout`-wrapped CLI runs (adw/_phases.py:479).
 */
export const TIMEOUT_RC = 124;

/**
 * Map the parent's abort reason: the invoker's timer aborts with
 * PHASE_TIMEOUT_ABORT_REASON (invoker.ts), and AbortSignal.timeout() raises a
 * 'TimeoutError' — both contain "timeout"; anything else is a cancel.
 */
export function abortKind(signal: AbortSignal): 'timeout' | 'cancelled' {
  const reason: unknown = signal.reason;
  const text =
    reason instanceof Error ? `${reason.name} ${reason.message}` : String(reason ?? '');
  return text.toLowerCase().includes('timeout') ? 'timeout' : 'cancelled';
}
