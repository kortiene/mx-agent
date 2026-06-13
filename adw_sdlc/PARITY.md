# adw_sdlc parity checklist (PLAN.md roadmap step 11)

This is the materialized **Section 10 parity checklist** and the **Section 8 cutover criteria** from
`adw_sdlc/PLAN.md`, with every box mapped to the test(s) that prove it. It exists so the cutover decision
(flip `MX_AGENT_ENGINE` default `py → ts`, roadmap step 12) is an audit against named, green tests rather
than a judgement call.

Two kinds of evidence are distinguished:

- **mocked-seams** — proven by the automated `adw_sdlc` (vitest) and Python `adw/` (unittest) suites, with
  every SDK/spawn/`gh`/git effect stubbed. No network, no API keys, no native binaries. This is the bulk
  of the checklist and is **complete for the `claude` cutover-gate runner**.
- **live** — requires a real-issue run against a real runner SDK with real credentials and spend. Not
  autonomously runnable (provider login, runner cost, a real GitHub issue). Tracked per runner in the
  [real-issue runs](#real-issue-runs-per-runner) table below.

Test files are under `adw_sdlc/test/` unless prefixed `adw/` (the Python half). Cited `it(...)` titles are
abbreviated.

---

## Section 10 parity checklist (for the shipped runner)

| Box | Status | Proven by |
|---|---|---|
| **Phase order & gating** — 9 agent phases + setup/finalize/ci-fix/merge/report in order; `e2e`/`document` conditional gates fire identically | ✅ mocked | `orchestrator.test.ts` *run() runs phases in order…*; `phases.test.ts` *conditional gates* (e2e whole-word hints, document doc-like files), *gateConditional fails loudly*; `engine-parity.test.ts` full chain ×4 runners |
| **Per-phase model routing** — exact tier ID per runner; `--model` > `MX_AGENT_MODEL_<PHASE>` > tier | ✅ mocked | `models-pricing.test.ts` *resolves tier defaults per runner*, *honors precedence*, *every runner has a complete tier map and classify stays on haiku* |
| **Selected runner edits the worktree unattended (capability parity)** — file/edit capability, `cwd=worktree`, edits-allowed mode | ✅ mocked | `runner-claude.test.ts` *tool grants + acceptEdits*; `runner-codex.test.ts` *coarse sandbox grants* (`workspace-write`/`never`); `runner-opencode.test.ts` *permission config*; `runner-pi.test.ts` request shape |
| **Structured output** — every phase yields a Zod-validated result; native-schema + fenced-JSON paths both validated; hard-failure ≤ fenced-JSON path | ✅ mocked / ⏳ live rate | `run-phase.test.ts` *native structured output*, *parses fenced JSON*, *nudges once then succeeds*, *retries native-schema WITH the contract it never saw*, *fails after the second parse failure*; `schemas.test.ts`; `phases.test.ts` *contract drift guard*. **Comparative hard-failure rate is a live metric** — see [methodology](#structured-output-hard-failure-rate). |
| **Secret withholding (fail-closed) — load-bearing, per runner** — child's observable spawned env excludes `GH_TOKEN`/`MATRIX_*`/`MX_AGENT_*`; new parent secret absent by default | ✅ mocked | `env.test.ts` *withholds GH_TOKEN and every deny-prefixed key*, *base ∪ runner row aligned with adw/_exec.py*; `runner-claude.test.ts` *only the allowlist when parent env poisoned*; `runner-codex-spawn.test.ts` *…NOTHING from the poisoned parent* + *no apiKey side door* (asserted on the **SDK-built child env**); `runner-opencode.test.ts` *never process.env*; `runner-pi.test.ts` *EXACTLY the request env*; lint gate `scripts/check-adw-sdlc-env.sh` |
| **Sandboxed-to-worktree (per runner)** — cwd/sandbox bound to worktree; per-tool veto only where `caps.perToolHook` | ✅ mocked | `runner-claude.test.ts` *denyGitGh (caps.perToolHook)* — git/gh denied, benign Bash allowed, fails closed outside grant; `runner-codex.test.ts` `workspace-write`; `runner-opencode.test.ts` *denies bash git/gh, never 'ask'*; matrix documents codex/opencode/pi as non-`perToolHook` |
| **Gated squash-merge** — `confirmMerge` refuses unattended without `--yes`/`MX_AGENT_YES=1` | ✅ mocked | `orchestrator.test.ts` *confirmMerge*: passes with `--yes`, *aborts unattended without --yes*, *honors an interactive yes/no* |
| **Bounded loops + no-retry-on-timeout** — `resolveLoop`/`patchLoop`/`ciFixLoop` cap attempts, stop on no-progress; timeout → `signal:'timeout'`, budget → `signal:'budget'`, both fail fast with no nudge | ✅ mocked | `orchestrator.test.ts` *resolveLoop* (caps attempts, stops on no progress), *patchLoop* (breaks on no progress), *ciFixLoop* (settles/exhausts/stops-on-no-change); `run-phase.test.ts` *fails fast with NO nudge on timeout*, *…on native budget signal*, *still accepts parseable output from a timed-out run* |
| **Resume** — `--adw-id --resume` skips done phases, reconstructs review findings for patch, short-circuits after merge; equivalent `state.json` | ✅ mocked | `orchestrator.test.ts` *resumes by skipping completed phases*, *short-circuits finalize after a recorded merge*, *recovers persisted review findings for the patch phase on resume*, *requires --adw-id with --resume*, *rejects resuming a run that belongs to a different issue* |
| **Artifacts** — `review`/`document` write `commit_message.txt`/`pr_body.md`, absorbed into state | ✅ mocked | `orchestrator.test.ts` *…absorbs artifacts…*; `phases.test.ts` *keeps artifact-file instructions on BOTH output paths* |
| **State equivalence (cross-language)** — `state.json` validates against `state.schema.json` and is loadable+resumable by Python `adw/` **and vice-versa** | ✅ mocked **(this PR)** | `adw/test_cross_language_state.py` + `cross-language-state.test.ts` (round-trip both directions, v1-projection equivalence, schema validation); `engine-parity.test.ts` (TS-side equivalence ×4 runners); `adw/test_state.py` `SchemaContractTests` |
| **Cost/usage** — `total_cost_usd`/`usage` per phase: native for claude/opencode/pi, parent-priced for token-only (codex, anthropic classify); claude native `maxBudgetUsd` honored | ✅ mocked | `models-pricing.test.ts` *costUsd* (prices classify + codex tiers, null for unpriced, table scoped to token-only); `orchestrator.test.ts` *poisons total_cost_usd to null once any phase cost is unknown*; `runner-claude.test.ts` *forwards maxBudgetUsd*, *maps native budget cap to signal 'budget'* |
| **adw/ green** — the unchanged Python `adw` suite stays green | ✅ | `python3 -m pytest adw/` (192 passed + 25 subtests as of this PR; only delta vs. pre-migration is additive `schema_version` + test-only files) |

---

## Section 8 cutover criteria (all must hold for `claude`)

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Section 10 checklist passes for `ts` with ≥ the `claude` runner | ✅ mocked | the table above (all boxes green for `claude`) |
| 2 | **State equivalence** — a `ts` run's `state.json` (i) validates against the schema, (ii) is loadable+resumable by Python `adw/` and vice-versa, (iii) matches v1 fields modulo additive keys | ✅ mocked **(this PR)** | `adw/test_cross_language_state.py` + `cross-language-state.test.ts` prove (i)/(ii)/(iii) directly; a completed live `claude` run (PR #331) produced a real such `state.json` |
| 3 | Templates byte-identical and shared (drift test green) | ✅ mocked | `phases.test.ts` *templatePath prefers .claude/commands… else .pi/prompts* (no fork); 14 shared basenames |
| 4 | **Secret-withholding proven per shipped runner** on the observable spawned env (codex asserted after the SDK builds the child env) | ✅ mocked | secret-withholding row above; `runner-codex-spawn.test.ts` drives the real 0.139.0 SDK over a mocked `spawn` |
| 5 | Squash-merge stays gated behind explicit confirmation in the `ts` path | ✅ mocked | `orchestrator.test.ts` *confirmMerge*; `cli.test.ts` flag plumbing |
| 6 | Python `adw/` suite stays green (only `schema_version` delta) | ✅ | `pytest adw/` green; production delta is the additive field only |

**Verdict for `claude`:** criteria 1–6 are satisfied under automated tests, and one real-issue run has
completed (PR #331, fix #332). The cutover (step 12) is unblocked for `claude` pending the maintainer's
sign-off on the live evidence below.

---

## Real-issue runs per runner

The capability-matrix rows are all green under mocks (per-adapter suites, steps 6–9). What remains is the
**live** half of step 11: one real GitHub issue driven end-to-end per runner, recording cost and the
structured-output hard-failure rate. These need credentials + spend + a human and are **not** autonomously
runnable.

| Runner | Live status | Detail / how to unblock |
|---|---|---|
| **claude** | ✅ done | Issue #304 → PR #331 (squash-merged), parity bug fixed in #332. Cost ≈ $34.76, run `007fd5ba`. On a box with no `ANTHROPIC_API_KEY` (CLI-OAuth only), the D1 default classify path fails — run with `MX_AGENT_CLASSIFY_ON_RUNNER=1`. |
| **codex** | ⛔ blocked | Live phase dies at classify: `refresh token was revoked` (OAuth access token expires ~1h; the refresh token comes back revoked server-side). `codex login status` reports success on local-file presence only. **Unblock:** `export OPENAI_API_KEY=…` (codex `RUNNER_ENV_ALLOW` already passes it; API-key mode skips the OAuth refresh entirely), or `codex logout && codex login` then run codex **immediately** (no long run in between). If a fresh token is also revoked within hours it is account-level — resolve with OpenAI. The transport is verified live (binary spawn, JSONL stream, `turn.failed` mapping); only the credential blocks a real phase. |
| **opencode** | ⏳ owed | Adapter + native-schema route verified live against the real 1.17.3 binary via a local stub provider (no credential) in step 8. A real-issue run needs a real provider key on `OPENCODE`'s allowlist row. |
| **pi** | ⏳ owed | Adapter + `--mode json` stream verified live against the real 0.79.1 binary via a scrubbed-agentDir stub provider (no credential) in step 9. A real-issue run needs a real provider key + Node ≥ 22.19 (the pi npm engines floor; the CI node-20 lane skips pi). |

A runner ships only when its capability-matrix row is satisfied **or** its phase falls back to the shared
`structuredCall` (classify) / another runner. Per-runner cutover is independent (PLAN.md Section 8);
`claude` is the only gate for the default flip.

---

## Structured-output hard-failure rate

The parity bar (Section 10) is: a native-schema backend's hard-failure rate — counting
`error_max_structured_output_retries` (claude), `StructuredOutputError` (opencode), and `null`
`parsed_output`/non-conforming payloads — must be **no worse** than the fenced-JSON+nudge path over the
parity runs.

- **Mechanism (mocked, proven):** every failure mode funnels into the same single-nudge-then-fail invoker
  path, validated in `run-phase.test.ts` (native non-conforming → one nudge; second failure → phase fails;
  native-schema nudge recomposes the prompt **with** the fenced-JSON contract footer the first prompt
  omitted — the fix from #332). So a native-schema backend can never fail *more* often than fenced-JSON for
  a structural reason; it has strictly more ways to succeed (native + fallback).
- **Rate (live, owed):** the empirical comparison is a property of real runs. Record per phase from each
  live run's `agents/{adw_id}/{phase}/transcript.log` (count nudge retries and terminal parse failures) and
  append to this section as runs complete. So far: `claude` PR #331 hit one tests-phase contract mismatch,
  root-caused and fixed structurally in #332 (Python truthiness coercion + native-schema nudge footer);
  no recurrence on resume.

---

## What remains for step 11

1. **codex** live run — unblock the credential (prefer `OPENAI_API_KEY`), run one real issue.
2. **opencode** live run — real provider key, one real issue.
3. **pi** live run — real provider key + Node ≥ 22.19, one real issue.
4. Append measured cost + hard-failure rate for each to the tables above.

Step 12 (cutover) is gated only on `claude` and is unblocked. Steps for the other three runners can land
after the default flip (per-runner cutover is independent).
