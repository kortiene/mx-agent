/**
 * adw_sdlc — TypeScript control plane for the phased ADW pipeline.
 *
 * Scaffold only: the orchestrator, AgentRunner seam, and the four runner
 * adapters land incrementally per adw_sdlc/PLAN.md (roadmap steps 3+). This
 * module currently fixes the two identifiers the rest of the plan hangs off.
 */

/** Engine identity recorded additively in state.json once runs are driven from TS. */
export const ENGINE = 'ts' as const;

/** The four interchangeable runner backends behind the AgentRunner interface (PLAN.md D1). */
export const RUNNER_IDS = ['claude', 'codex', 'opencode', 'pi'] as const;

export type RunnerId = (typeof RUNNER_IDS)[number];
