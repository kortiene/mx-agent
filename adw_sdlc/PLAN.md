# ADW → adw_sdlc Migration Plan (TypeScript, four interchangeable runners)

Re-architect the CLI-subprocess ADW pipeline (`adw/`, Python) into a new **TypeScript/Node** package
(`adw_sdlc/`) that drives the agentic phases through **one common `AgentRunner` interface** backed by
**four interchangeable runners** — `claude` (Claude Agent SDK), `pi` (pi-node), `codex` (OpenAI Codex
SDK), `opencode` (sst/opencode) — while preserving every security and control-flow property of `adw/`
and keeping `adw/` green until parity is reached.

**Why TypeScript, why four runners.** All four target runners are Node/TypeScript-native: `pi` is
"pi-node"; `codex` ships `@openai/codex-sdk`; `opencode` ships `@opencode-ai/sdk`; the Claude Agent SDK
ships for TypeScript as `@anthropic-ai/claude-agent-sdk`. A TypeScript control plane lets each runner use
its native SDK (typed structured output, programmatic tool/permission control, usage/cost) instead of
fragile stdout parsing. A user selects the runner via `--runner {claude|pi|codex|opencode}` /
`MX_AGENT_RUNNER`, mirroring today's `pi`/`claude` selection (`adw/_orchestrator.py:557`,
`adw/_runner.py:28`).

**Consequence for D4.** A TypeScript `adw_sdlc` **cannot import** the Python `adw_core` from the prior
plan, so the prior D4 (shared in-process control plane) is physically impossible across the
Python↔TypeScript boundary. The control plane is **reimplemented in TypeScript**, and the
`agents/{adw_id}/` workspace — `state.json` + per-phase `prompt.txt`/`transcript.log` +
`commit_message.txt`/`pr_body.md` — becomes the **sole cross-language contract** with the still-Python
`adw/`.

Status: **plan, not a rewrite.** Decisions D1–D6 are settled (Section 2). Implementation is incremental
(Section 11). Facts verified against the live tree or installed/published type definitions are cited at
`adw/*.py:line` or `<pkg>@<ver> <file>:line`; facts the research left uncertain are marked **[VERIFY]**
and appear as roadmap steps, never as assertions. **Two formerly-[VERIFY] claims have now been resolved
from the shipped `.d.ts` and are stated as fact:** (a) the Claude Agent SDK already spawns the Claude
Code executable as a child process and its `options.env` **replaces** (does not merge) `process.env`,
and (b) `pi` ships a full in-process Node SDK (`createAgentSession`) that reports cost natively. See the
"## Changelog vs draft" section for the full list of review fixes folded into this revision.

---

## 1. Goal & scope

### Goal

Replace the runner seam — `adw/_runner.py` `build_runner_command()` → `subprocess.Popen` in `_stream_to()`
(`adw/_runner.py:31-124`) — with a **single TypeScript `AgentRunner.runPhase()` seam** that any of four
native runner adapters can satisfy, so per-phase structured output, model routing, and cost/usage come
from each runner's SDK natively, **without** changing the deterministic control plane's semantics, git/gh
ownership, or the secret-withholding boundary. A non-negotiable corollary: because today's agent is an
external CLI with full filesystem access in the repo `cwd` that does its own code reading and editing,
the selected runner **must be granted** equivalent unattended read/edit access to the working tree
(Section 4). Removing git/gh without granting file-editing capability would turn every editing phase into
a no-op; preserving the agent's full-fs editing capability is as load-bearing as withholding secrets.

The TS Claude SDK preserves today's `CLAUDE_BIN` ergonomics natively: `Options.pathToClaudeCodeExecutable`
("Uses the built-in executable if not specified") plus `executable:'bun'|'deno'|'node'` are the direct
analogue of `adw/`'s resolvable-binary-on-PATH model — set the path from the resolved binary and keep
`PATH`/`HOME` in the per-runner allowlist so the SDK's chosen runtime can be located and spawned. This is
**resolved now**, not a runtime unknown (verified: `@anthropic-ai/claude-agent-sdk` `sdk.d.ts`,
`pathToClaudeCodeExecutable` + `executable` + "checks if the executable exists before spawning").

### In scope

- A new sibling package `adw_sdlc/` (TypeScript/Node) that **reimplements** the deterministic control
  plane (state machine, the three bounded loops, phase ordering + conditional gates, no-retry-on-timeout,
  all git/gh via `child_process`) with byte-for-byte-equivalent **semantics** to `adw/` (per D4).
- **One `AgentRunner` interface** (D6) with a single `runPhase()` seam plus optional `start()/stop()`,
  and **four backend adapters** (`runner-claude.ts`, `runner-pi.ts`, `runner-codex.ts`,
  `runner-opencode.ts`), gated by a per-runner **capability matrix** (Section 5).
- A shared **`structuredCall<T>()`** helper on `@anthropic-ai/sdk` for the single `classify` phase,
  defaulting to `claude-haiku-4-5` for **all** runners (D1).
- `MX_AGENT_ENGINE={py|ts}` to select which language drives a run (orthogonal to `MX_AGENT_RUNNER`),
  default `py`; cutover = flip default to `ts` once parity holds.

### Non-goals

- **No shared code across the Python↔TS boundary** — `adw/` stays standalone; `state.json` is the
  cross-language contract (D4). The prior plan's `adw_core` shared package is dropped.
- **No control plane on LlamaIndex.TS `AgentWorkflow`** — the security-critical loops stay plain
  TypeScript (D2).
- **No LlamaIndex.TS on the structured-output path** — each runner's native schema output + a shared Zod
  validate-once shim replaces it (D2).
- **No agent-side git/gh** — the TS orchestrator keeps owning all git/gh; the squash-merge stays gated
  behind explicit confirmation (D5).
- **No cross-run institutional-memory / RAG module in this plan.** Orthogonal to the migration goal; it
  carries no embedding-stack surface and is spun out as a separate post-cutover proposal, evaluated on
  its own merits (not pre-committed to LlamaIndex.TS) (D2).
- **No requirement that all four runners ship at launch** — land iteratively behind the interface; one
  runner (`claude`) at parity is the cutover gate (D1).
- **No big-bang cutover, no deleting `adw/`** until one clean release with the `ts` engine default (D4).
- **No stdlib-only / Python constraints** for `adw_sdlc` (it is a Node/TS package; D3).

---

## 2. Resolved decisions (settled)

### D1 — Four-runner backend strategy & SDK selection

**Choice:** Per-backend native integration behind **one `AgentRunner` interface**, with pinned bindings:
`claude` → `@anthropic-ai/claude-agent-sdk` (`query()`, native child-process spawn, `options.env`
replace-semantics — Section 4.3-1); `pi` → `@earendil-works/pi-coding-agent` **in-process SDK**
(`createAgentSession`, with `AuthStorage`/`agentDir` credential isolation) driven through a **CLI/owned-
subprocess boundary** for the hard env requirement; `codex` → `@openai/codex-sdk` (lockstep with the
native `@openai/codex` binary); `opencode` → `@opencode-ai/sdk` **v2 client** (`@opencode-ai/sdk/v2`,
the only surface that supports `format:{json_schema}` → `result.structured`) over a **self-spawned**
`opencode serve` (not `createOpencodeServer`). `classify` is the only pure single-structured phase → by
default it runs on the shared `@anthropic-ai/sdk` `messages.parse` + `zodOutputFormat(ClassifySchema)`
with `claude-haiku-4-5` **regardless of selected runner** (opt-out `MX_AGENT_CLASSIFY_ON_RUNNER=1`). The
other 8 agentic phases run on the selected runner. Native budget gating and native cost are used wherever
a backend provides them (`claude` `maxBudgetUsd`/`total_cost_usd`; `opencode`/`pi` native cost); a
parent-side price table is the **fallback for token-only backends only** (`codex`, the `anthropic`
classify call). Land iteratively: **claude → codex → opencode → pi**; `claude` at parity is the cutover
gate.
**Rationale (1-line):** The four backends are genuinely heterogeneous on exactly the axes the hard
requirements care about, so one uniform mechanism is impossible — but one interface over four native
adapters gives typed structured output, programmatic permission/env control, and usage/cost that stdout
parsing cannot.
**Key rejected:** Drive all four as uniform CLI subprocesses with fenced-JSON parsing — throws away the
rewrite's entire value (typed output, env-replace allowlists, resume-by-session-id) and re-introduces the
fragile trailing-fenced-JSON contract everywhere instead of only where unavoidable (pi).

### D2 — LlamaIndex.TS role

**Choice:** **None in this plan.** Each runner + the shared `classify` path already produce
schema-validated output natively (`@anthropic-ai/sdk` `messages.parse`; Agent SDK `outputFormat`; codex
`outputSchema`; opencode v2 `format:{json_schema}`; pi prompt-and-parse), so a LlamaIndex.TS provider
layer is strictly additive. Control flow stays plain TypeScript (the hard requirements forbid ceding the
loop to `AgentWorkflow`). Cross-run memory / RAG (the only non-redundant idea) stays **deferred,
post-parity, out of scope**, and is not pre-committed to LlamaIndex.TS.
**Rationale (1-line):** The four-runner requirement makes native structured output *more* attractive, not
less — three of four already speak Zod/JSON-schema and the fourth (pi) parses fenced JSON, so
normalization is a thin Zod-validate-once shim; a fifth abstraction removes nothing.
**Key rejected:** LlamaIndex.TS `responseFormat`/`exec` for per-phase output across all runners — routes
through `@llamaindex/anthropic`/`@llamaindex/openai` wrapping the same native mechanisms, adding a heavy
dependency tree and a second failure surface while covering neither `pi` nor arbitrary opencode providers.

### D3 — TypeScript toolchain, runtime, deps & CI

**Choice:** Node-LTS (`engines >=20.19`, the floor imposed by the locked vitest/vite toolchain; CI matrix 20 + 22) **ESM-only** TypeScript package managed by
**pnpm** (committed `pnpm-lock.yaml`, `pnpm-workspace.yaml` member `adw_sdlc/`). `tsc` for
typecheck/emit; `tsx` for dev/CI run; `vitest` for tests. The four runner SDKs are
**`optionalDependencies`** reached only through **dynamic `await import()`** inside a registry (the TS
analogue of the Python lazy-import rule) so installing/selecting one runner never requires the other
three (and their native binaries). `@anthropic-ai/sdk` (classify) + `zod` (validation) are the only
non-optional runtime deps. New hermetic `adw_sdlc` CI job (`pnpm install --frozen-lockfile`,
`pnpm run typecheck`, `pnpm run test`) with every SDK replaced by `vi.mock` stubs — no network, no API
keys, no native binaries; the existing Python `adw` job stays byte-for-byte untouched. A **lint/grep
gate + unit test** asserts no runner module ever spreads `...process.env` and that the codex adapter
**always** passes an explicit `env` (omitting it flips codex from no-inherit to full-inherit — Section
4.3-2).
**Rationale (1-line):** Node is the only runtime all four backends are validated against (three drive
native binaries), and pnpm + optionalDeps + dynamic-import is the idiomatic re-resolution of "extras +
lazy imports keep the base install lean" under four heavyweight native-binary backends.
**Key rejected:** Bun/Deno runtime — `node:child_process`/native-addon compatibility for the specific
codex/opencode/pi binaries and the env-allowlist behavior are unverified, turning a settled hard
requirement into a research risk for no benefit on an internal orchestrator.

### D4 — Coexistence & cutover via a versioned `state.json` contract

**Choice:** **Reimplement** the control plane in TypeScript (no shared package). Python `adw/` stays
as-is. The `agents/{adw_id}/` workspace is the **sole cross-language contract**. Treat the Python
`AdwState` dataclass (`adw/_state.py:51-67`) as canonical **v1**; add one `schema_version` field to both
sides as the first, tiny cutover PR; all TS additions (`total_cost_usd`, per-phase `usage`,
`session_id`/`thread_id`, `runner`, `engine`) are **additive-only** (Python's `load()` already drops
unknown keys, `adw/_state.py:120-143`). Codify the schema in one `adw/state.schema.json` tested from
**both** Python and TS. Templates (`.pi/prompts/*.md`, `.claude/commands/*.md`) stay shared verbatim.
`MX_AGENT_ENGINE={py|ts}` (default `py`) picks the language; per-runner cutover is independent and
criteria-based; `adw/` remains the fallback engine for ≥1 stable release.
**Rationale (1-line):** TS cannot import Python `adw_core`, so the only thing two separate-language
processes can share is data-on-disk + text templates; the codebase already engineered `agents/{adw_id}/`
as the resume/observability boundary, so it *is* the contract.
**Key rejected:** A Python sidecar (Node→Python→runner) — defeats the language pivot, doubles the
secret-handling surface, adds a fragile process layer, and keeps Python on the critical path forever.

### D5 — Secret-withholding via an orchestrator-owned process boundary + deny-by-default allowlist

**Choice:** The load-bearing secret boundary is **always a real OS process boundary the TS orchestrator
owns**: every runner is driven as a child the orchestrator spawns itself (or, for `claude`, via the SDK's
own child spawn with an explicit replacing `env`) with `child_process.spawn(cmd, args, { env: allowlist })`
semantics, where `allowlist` comes from a single ported `safeSubprocessEnv()` (the Node analogue of
`adw/_exec.py:118-141` `safe_subprocess_env`: allow `HOME/USER/PATH/SHELL/TERM/LANG/LC_ALL/TMPDIR` + each
runner's required credential keys **only**; never spread `process.env`; never `GH_TOKEN` in phased mode;
never any `MATRIX_*`/`MX_AGENT_*` key — deny prefixes verified at `adw/_exec.py:115`). For `claude`,
`Options.env` **is** the boundary because it is verified to **replace** `process.env` (not merge) and the
SDK already spawns the Claude Code executable as a child — there is no need to fork a Node child ourselves
(Section 4.3-1). For backends whose env option is non-replacing or unverified, the boundary is the
orchestrator-owned spawn. `classify` is exempt (no tools, no shell): it runs in-process with only
`ANTHROPIC_API_KEY`.
**Rationale (1-line):** Secret-withholding is only enforceable across an OS process boundary (an agent
with Bash/file tools can read its own env, `~/.netrc`, auth files, and shell out), and three of four SDKs
already give a real OS boundary with an explicit/replacing env — so centralizing on "the env object that
reaches the spawned child is the allowlist and nothing else" reduces the guarantee to one auditable code
path per runner.
**Key rejected:** Rely on a *merging* env option, or on each SDK's in-process state, as the boundary —
opencode's `createOpencodeServer` hardcodes `{...process.env}` (leaks), pi's SDK runs in-process (no
boundary unless we own the spawn); betting the guarantee on a merge-on-top option would be fail-open the
moment one merges.

### D6 — The common four-runner interface: `AgentRunner` with one `runPhase()` seam

**Choice:** Define **one** TypeScript interface, `AgentRunner`, that the orchestrator calls exactly once
per agentic phase (`runPhase(req: PhaseRequest) → PhaseResult`), plus optional `start()/stop()` so
opencode's server lifecycle hides behind no-ops for the in-process backends. The control plane branches
**only on `runner.caps` (a capability matrix)**, never on runner identity. Structured output is a
**first-class capability decoupled from the agentic backend**: `classify` goes through the shared
`structuredCall<T>()` (Anthropic SDK), not `runPhase()`. The single nudge-retry and the
no-retry-on-timeout mapping live **once** in the invoker layer over `runPhase`, preserving the verified
AS-IS semantics (`adw/_phases.py:482-516`).
**Rationale (1-line):** `adw/_phases.run_agent_phase(...) -> dict` is already this exact shape, so one
`runPhase` seam + a `RunnerCaps` matrix + optional `start/stop` is the minimal surface that normalizes
four heterogeneous backends without leaking heterogeneity into the DRY, runner-agnostic control plane.
**Key rejected:** A fat interface with `invoke()`/`getStructuredOutput()`/`setPermissions()`/`getUsage()`/
`captureTranscript()` — multiplies the surface four adapters must implement and re-leaks heterogeneity
into the control plane; usage/cost/transcript are *results* of the one call, not separate operations.

---

## 3. Target architecture

### 3.1 Package layout (TypeScript, no shared `adw_core`)

```text
mx-agent/
├── adw/                       # UNCHANGED (Python, standalone). Only delta pre-cutover: + schema_version.
│   └── state.schema.json      # NEW: single JSON-Schema for state.json, tested from BOTH Python and TS
│
├── adw_sdlc/                  # NEW TypeScript/Node package (full orchestrator + 4 runner adapters)
│   ├── package.json           # name "adw-sdlc"; ESM ("type":"module"); engines >=20.19  (D3)
│   ├── tsconfig.json          # target ES2022, moduleResolution nodenext, declaration
│   ├── tsconfig.build.json
│   ├── src/
│   │   ├── orchestrator.ts     # run, resolveLoop, patchLoop, ciFixLoop, gates; seams via OrchestratorDeps (D4)
│   │   ├── phases.ts           # AGENT_PHASES, TEMPLATE, OUTPUT_CONTRACT, gates,
│   │   │                       #   composePhasePrompt, buildFooter, templatePath, ARTIFACT_PHASES
│   │   ├── state.ts            # AdwState (+ schema_version, additive fields), load/save, workspace
│   │   ├── git.ts              # ALL git/gh via child_process (mirrors adw._git semantics)            (D5)
│   │   ├── env.ts              # safeSubprocessEnv, BASE_ENV_ALLOW, ENV_DENY_PREFIXES, per-runner keys (D5)
│   │   ├── common.ts           # REPO_ROOT, template render/substitution, fenced-JSON parse (adw/common.py)
│   │   ├── exec.ts             # capture/ghJson, console notes, progress comments, gh/repo queries (adw/_exec.py)
│   │   ├── issue.ts            # deriveBranch/slugify/fetchIssue/setStatus (adw/work_issue.py helpers)
│   │   ├── invoker.ts          # AgentRunner / PhaseRequest / PhaseResult / RunnerCaps types         (D6)
│   │   ├── run-phase.ts        # the invoker layer over runPhase: single nudge + no-retry-on-timeout (D6)
│   │   ├── structured-call.ts  # structuredCall<T>() on @anthropic-ai/sdk for classify                (D1)
│   │   ├── registry.ts         # MX_AGENT_RUNNER -> dynamic import() of the adapter (optionalDeps)     (D3)
│   │   ├── models.ts           # tier->modelId per runner; exact model-ID constants
│   │   ├── pricing.ts          # price table for TOKEN-ONLY backends only (codex, anthropic classify)
│   │   ├── schemas.ts          # Zod result schemas (replaces Pydantic models)
│   │   ├── tools.ts            # per-phase tool grants / sandbox / permission config
│   │   ├── runners/
│   │   │   ├── runner-claude.ts    # @anthropic-ai/claude-agent-sdk: query() + options.env allowlist
│   │   │   ├── runner-codex.ts     # @openai/codex-sdk (env-no-inherit; env ALWAYS passed)
│   │   │   ├── runner-opencode.ts  # @opencode-ai/sdk/v2 client + SELF-SPAWNED opencode serve
│   │   │   ├── runner-pi.ts        # pi in-process SDK over an owned subprocess boundary (event-bus capture)
│   │   │   └── runner-mock.ts      # test/parity mock runner
│   │   └── child/
│   │       └── spawn-child.ts      # CONTINGENCY ONLY: forked clean-env entrypoint (not on the default path)
│   └── test/                   # vitest; mock each SDK via vi.mock (no network/keys)
│
├── pnpm-workspace.yaml         # member: adw_sdlc/                                                     (D3)
└── pnpm-lock.yaml              # committed                                                             (D3)
```

`adw_sdlc` (ts engine) drives `orchestrator.run(runner)`; `adw/` (py engine) is untouched. The
orchestrator logic is reimplemented with identical semantics — verified only via state equivalence
(Section 8/10), not a shared module. **Note:** there is no dedicated `child/claude-child.ts` on the
default path; `claude` uses `options.env` directly (Section 4.3-1). `child/spawn-child.ts` exists only as
a documented contingency if a future SDK version is ever proven to *merge* env (Section 4.5).

### 3.2 The runner interface (`invoker.ts`) — the single seam (D6)

```ts
export interface PhaseRequest<T = unknown> {
  phase: string;                 // plan|implement|tests|resolve|e2e|review|patch|document (classify is special)
  prompt: string;                // composed (preamble+context+body+footer) by the TS control plane
  model: string;                 // resolved tier->modelId for THIS runner (per-runner registry)
  reasoning?: 'minimal' | 'low' | 'medium' | 'high'; // tier->effort hint; runner maps or ignores
  cwd: string;                   // the worktree the agent edits
  env: Record<string, string>;   // EXPLICIT allowlist the orchestrator built; the ONLY env the backend may use
  schema?: JsonSchema;           // per-phase JSON Schema (from Zod); absent => free-form
  maxBudgetUsd?: number;         // forwarded to backends with native budget gating (claude)
  transcriptPath: string;        // agents/{adw_id}/{phase}/transcript.log
  signal: AbortSignal;           // orchestrator-owned timeout/cancel
}
export interface PhaseResult {
  ok: boolean;
  structured: Record<string, unknown> | null; // normalized dict; validated by the parent with Zod
  transcriptText: string;                       // also teed to transcriptPath during the run
  usage: { inputTokens?: number; outputTokens?: number; cachedInputTokens?: number;
           reasoningTokens?: number; costUsd?: number | null }; // native where available; parent fills token-only
  rc: number;                                   // 0 ok; nonzero failure feeds bounded loops
  signal: 'none' | 'timeout' | 'cancelled' | 'budget'; // drives no-retry-on-timeout; 'budget' = native cap hit
  sessionId?: string;                           // for resume where the backend supports it
}
export interface RunnerCaps {
  nativeSchema: boolean;       // backend constrains output to schema (claude/codex/opencode-v2 = true; pi = false)
  perToolHook: boolean;        // programmatic per-tool veto (claude=true; codex=false; opencode=event; pi=event)
  envIsolation: 'explicit-no-inherit' | 'subprocess-allowlist';
  costUsd: boolean;            // backend reports dollars natively (claude/opencode/pi = true; codex = false)
  nativeBudget: boolean;       // backend enforces maxBudgetUsd itself (claude = true; others = false)
  resume: boolean;             // sessionId resume supported
}
export interface AgentRunner {
  readonly id: 'claude' | 'pi' | 'codex' | 'opencode';
  readonly caps: RunnerCaps;
  start?(): Promise<void>;     // opencode spawns/awaits its server; others no-op
  runPhase(req: PhaseRequest): Promise<PhaseResult>;
  stop?(): Promise<void>;      // opencode kills its server; others no-op
}
```

Binding rules:

- **classify is NOT `runPhase`.** It goes through `structuredCall<T>(model, messages, schema)` on
  `@anthropic-ai/sdk` (`messages.parse` + `zodOutputFormat`), default `claude-haiku-4-5`, regardless of
  selected runner (opt-out `MX_AGENT_CLASSIFY_ON_RUNNER=1`).
- **Every other agentic phase** goes through the selected `runner.runPhase()`.
- **Nudge-retry + no-retry-on-timeout live in the invoker, once** (Section 7): on `signal==='timeout'`
  the invoker raises `AdwError` *without* a nudge (preserving `_TIMEOUT_EXIT_CODES` semantics); only a
  parse failure on a non-timed-out run triggers the single nudge-retry (`_NUDGE`). `signal==='budget'`
  (claude's native `error_max_budget_usd`) also fails fast with **no** nudge.

### 3.3 How the TS orchestrator owns git/gh

All git/gh lives in `src/git.ts`, invoked **only by the parent process** via `child_process` (no runner
ships git/gh tools, and none receives `GH_TOKEN` in phased mode). The **load-bearing** boundary is that
each runner child's env is the allowlist `safeSubprocessEnv()` built with `GH_TOKEN` absent, so any
git/gh the agent's Bash *could* still invoke fails closed (Section 4). The squash-merge stays gated
behind explicit confirmation (`--yes`/`MX_AGENT_YES=1`/tty) in the orchestrator, mirroring `confirm_merge`
(`adw/_orchestrator.py:85-96`).

### 3.4 Where LlamaIndex.TS sits

**Nowhere** in the base migration (D2). Zero LlamaIndex surface in `package.json`, the control plane, or
the structured-output path. The deferred cross-run-memory proposal is the only place an embedding stack
could later earn a place, and it is tracked as a separate post-cutover issue (not on the parity-critical
path, not pre-committed to LlamaIndex.TS).

---

## 4. Security model (per D5)

### 4.1 Threat defended & why a *merging* env option would not be the boundary

A secret present in the orchestrator's environment (`GH_TOKEN`, `MATRIX_*`, `MX_AGENT_*`, device keys)
must **never** reach the agent **by default** — including secrets added in the future. An agent with
Bash/file tools can read its own process env, `~/.netrc`, auth files, and shell out (`git push`, `gh`,
`env`). The boundary is therefore "the env object that reaches the spawned child is exactly the allowlist".
The SDKs' env semantics are heterogeneous but, for three of four, now **verified to give a replacing /
explicit env on a real child process**:

| Runner | SDK env behavior | Verified? |
| --- | --- | --- |
| `claude` | `options.env` **replaces** `process.env` ("Environment variables to pass to the Claude Code process. Defaults to `process.env`"), and `query()` spawns the Claude Code executable as a **child** (`pathToClaudeCodeExecutable`/`executable`) | **verified** on disk (`@anthropic-ai/claude-agent-sdk` `sdk.d.ts`, `env`/`pathToClaudeCodeExecutable`/`executable`) |
| `codex` | `CodexOptions.env`, when set, **does not inherit** `process.env` (full replace); `apiKey` is injected as `CODEX_API_KEY`; spawns native child | **verified** (`@openai/codex-sdk` 0.139.0 `dist/index.js:231-249`) |
| `opencode` | `createOpencodeServer` **hardcodes** `{...process.env}` (leaks) → **self-spawn `opencode serve` instead** | **verified** (`@opencode-ai/sdk` 1.17.3, `createOpencodeServer` `process.env` leak) |
| `pi` | runs **in-process** (`createAgentSession`), no env option → **own the spawn boundary** (and use `AuthStorage`/`agentDir` to isolate credentials) | **verified** (`@earendil-works/pi-coding-agent` `dist/core/sdk.d.ts`, `agentDir`/`authStorage`) |

Because `claude` and `codex` give a **replacing** env on a real child, their adapters pass the allowlist
as the SDK's `env` directly (no bespoke fork). `opencode` and `pi` get the boundary from the
orchestrator-owned spawn. This reduces the guarantee to one auditable chokepoint per runner (does the env
object that reaches the child ever spread `process.env`? no), exactly mirroring the single
`safe_subprocess_env` the Python pipeline relies on today (`adw/_exec.py:118-141`).

### 4.2 The capability grant (parity-critical, like the Python plan's 4.2)

Today the agent **is** an external CLI with full-fs access; it reads and edits the working tree itself.
Each runner must be granted **equivalent unattended read/edit capability**, or `implement`/`tests`/
`resolve`/`patch`/`document` become no-ops:

- `claude` — `allowedTools: ["Read","Write","Edit","Glob","Grep"]` **plus** a `canUseTool` callback that
  mediates Bash (denies git/gh, allows the rest) and fails closed on tools outside the grant;
  `permissionMode:"acceptEdits"`, `cwd=worktree`. Bash is deliberately **not** in `allowedTools`: an
  allowedTools entry is an allow *rule* that resolves before `canUseTool`, which would make the git/gh
  veto dead code (verified by live probe in step 6).
- `codex` — `sandboxMode:"workspace-write"`, `approvalPolicy:"never"`, `workingDirectory=worktree`,
  `skipGitRepoCheck:true`. (Tool control is **coarse** — sandbox + policy only; no per-tool veto.)
- `opencode` — `config.permission` `{"*":"allow", "bash":{"rm *":"deny", ...}}`; **never** `"ask"`
  (hangs headless). cwd via the self-spawned server's `cwd`.
- `pi` — built-in `read/write/edit/bash/grep/find/ls` tools (SDK `createCodingTools`/`tools`/
  `excludeTools`), `cwd=worktree`, `agentDir`/`authStorage` for credential isolation.

### 4.3 Per-runner concretization of the process boundary (the load-bearing control)

A shared `safeSubprocessEnv()` centralizes env construction so adding a runner cannot accidentally inherit
`process.env`. Phased mode always builds the allowlist with `allow_gh_token=false`.

1. **claude** — the Agent SDK **already spawns the Claude Code executable as a child process** and
   `options.env` **replaces** `process.env` (verified: `sdk.d.ts` `env` doc "Defaults to `process.env`",
   plus `pathToClaudeCodeExecutable`/`executable`/"checks if the executable exists before spawning"). So
   the secret boundary the design wants is achieved by passing the `safeSubprocessEnv()` allowlist
   directly as `options.env` — **no bespoke Node fork**. Set `pathToClaudeCodeExecutable` from the
   resolved binary (the `CLAUDE_BIN` analogue) and keep `PATH`/`HOME` in the allowlist so the SDK's chosen
   `executable` runtime can be located/spawned. Allowlist = `{base, ANTHROPIC_API_KEY (or
   ANTHROPIC_AUTH_TOKEN), CLAUDE_* config}`. **Contingency only:** keep `child/spawn-child.ts` as a
   fallback if a *runtime* test on a future pinned version ever proves merge-not-replace semantics; do
   **not** put it on the default path.
2. **codex** — pass the allowlist as `CodexOptions.env` (verified not to inherit `process.env`,
   `dist/index.js:231-239` replaces onto `{}`); prefer `apiKey` (injected as `CODEX_API_KEY`,
   `dist/index.js:244-245`) or whitelist `OPENAI_API_KEY`/`CODEX_API_KEY`. Allowlist = `{HOME, PATH,
   CODEX_API_KEY|OPENAI_API_KEY}`. The adapter **must always supply `env`** (omitting `CodexOptions.env`
   makes the SDK copy *all* of `process.env`, `dist/index.js:234-239`) — enforced by a unit test +
   lint/grep gate (Section 9/10). **Lockstep guard:** because the credential reaches the child via
   `apiKey`→`CODEX_API_KEY` *regardless* of the env allowlist, the secret-withholding test must assert on
   the **spawned child env the SDK builds**, not just the allowlist object the adapter passes in —
   otherwise a provider key could flow via `apiKey` while the env test still passes.
3. **opencode** — **do not** use `createOpencodeServer` (it hardcodes `{...process.env}`). Self-spawn
   `child_process.spawn('opencode', ['serve','--hostname','127.0.0.1','--port',N], {cwd: worktree, env: allowlist})`,
   scrape stdout for the listening banner, then connect with the **v2 client** —
   `import { createOpencodeClient } from '@opencode-ai/sdk/v2'` — because `format:{json_schema}` →
   `result.structured` exists **only** in the v2 surface (`dist/v2/gen/types.gen.d.ts`:
   `OutputFormatJsonSchema`, `structured?`). The v1 default export (`'.'`) cannot do native schema. Allowlist
   = `{base, ANTHROPIC_API_KEY/OPENAI_API_KEY/provider keys, optional OPENCODE_SERVER_PASSWORD}`. Server is
   long-lived per run, managed behind `start()/stop()`.
4. **pi** — `@earendil-works/pi-coding-agent` ships a **full in-process Node SDK** (`createAgentSession`,
   `AgentSession`, `RpcClient`, `runPrintMode`/`runRpcMode`, programmatic tools), and crucially
   `AuthStorage` + `agentDir` injection (a credential-isolation primitive *stronger* than env scrubbing).
   Because the SDK is in-process, the **secret boundary is an orchestrator-owned subprocess**: the
   landed adapter (step 9) spawns the **CLI in `--mode json`** — print mode subscribes to the same
   `AgentSession` event bus and writes one JSON event per stdout line (`dist/modes/print-mode.js`), so
   the orchestrator-owned spawn and the event-bus capture are the *same mechanism* — with the allowlist
   env, and additionally points `agentDir` at a scrubbed throwaway dir holding only the needed provider
   auth via `PI_CODING_AGENT_DIR` (read by `getAgentDir()`, `dist/config.js:393-398`; provider keys
   resolve auth.json → env → models.json fallback, pi-ai `dist/env-api-keys.js`). Allowlist = `{base,
   provider key (ANTHROPIC_API_KEY|OPENAI_API_KEY), PI_BIN/PI_MODEL/PI_THINKING,
   PI_CODING_AGENT_DIR/PI_CODING_AGENT_SESSION_DIR}`. **Output is captured via the event bus, not a
   return value:** the adapter accumulates assistant `text_delta`s and per-message `usage` (incl. native
   `usage.cost.total` dollars) from the `message_update`/`message_end` events on the line stream, then
   applies the fenced-JSON+nudge contract. `pi` has **no** native JSON-schema-constrained output
   (`PromptOptions` has no `responseFormat`), so `caps.nativeSchema=false` — correct, and the only pi
   capability that remains "weak".

### 4.4 Transitive-leak handling & residual surface

- Any grandchild a runner spawns (opencode server → tools; codex/pi sandboxes) inherits the **clean
  child env**, so the OS boundary contains transitive leakage. **For codex this is contingent on the
  adapter always passing `CodexOptions.env`** — if omitted, the SDK copies all of `process.env` and
  grandchildren inherit everything (`dist/index.js:234-239`); the always-pass-env test/lint gate (Section
  9/10) closes that regression risk.
- **HOME-reachable credential files are a residual surface** the env allowlist alone does not close:
  `~/.pi/agent/auth.json` (pi), `~/.codex/auth.json` (codex), `~/.local/share/opencode/auth.json`
  (opencode) may interpolate shell commands or hold provider secrets. **[VERIFY]/decide per runner**
  whether `HOME` is required and whether to point `HOME` (and, for pi, `agentDir`/`authStorage`) at a
  scrubbed throwaway dir containing only the needed provider auth.
- **Per-tool veto exists only for `claude`** (`canUseTool`); `codex` is sandbox-only; `opencode`'s and
  `pi`'s are event-driven. The parity line becomes "the selected runner withholds secrets AND is
  sandboxed to the worktree", not "every runner offers a per-tool callback". `caps.perToolHook` makes
  this explicit.
- **Best-effort prompt-level nudge:** `PHASE_PREAMBLE_SHARED` ("Python/TS owns git/gh; do NOT run git/gh;
  no token in env") is carried verbatim (`adw/_phases.py:371-396`) and applied to all runners as the
  first line of defense — **not** a checkable boundary.

### 4.5 How this differs from the Python spawn-scrub

The dropped Python D5 cleared `os.environ` in a `multiprocessing` spawn child *before* importing the SDK
because the *Python* `ClaudeAgentOptions.env` was believed to merge fail-open. That premise does **not**
carry to the TypeScript Agent SDK: `@anthropic-ai/claude-agent-sdk` already spawns the Claude Code
executable as a child and `options.env` **replaces** `process.env`, so passing the allowlist as
`options.env` *is* a clean-env OS boundary with no clear-before-import ordering hazard. For `codex` the
SDK does the same replace (a no-op extra); for `opencode`/`pi` the orchestrator-owned spawn provides it.
A bespoke Node fork (`child/spawn-child.ts`) is therefore **contingency only** — kept solely to re-arm
the "scrub before the SDK runs" boundary if a future pinned version is ever proven to merge env (a
runtime test, not a doc reading). `classify` stays in-process (no tools, no shell, only `ANTHROPIC_API_KEY`
— already allowlisted, `adw/_exec.py`).

---

## 5. Runner capability matrix

Tiers are runner-agnostic (capable/mid/cheap); model IDs are per-runner. `[VERIFY]` marks facts not
confirmed on disk (Section 12). `costUsd=no` = token-only (parent computes from `pricing.ts`).

| Dimension | `claude` | `codex` | `opencode` | `pi` |
|---|---|---|---|---|
| **Integration** | native SDK (spawns Claude Code child via `options.env`) | native SDK (spawns native binary; env always passed) | **v2 SDK + self-spawned server** | **CLI `--mode json` event stream over owned subprocess** |
| **Package (pin)** | `@anthropic-ai/claude-agent-sdk` `^0.3.170` | `@openai/codex-sdk` `0.139.0` (+ `@openai/codex` lockstep) | `@opencode-ai/sdk` `^1.17.3` (**v2 client subpath**) | `@earendil-works/pi-coding-agent` (npm resolves `0.79.1`) |
| **Auth / credential** | `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` | `apiKey`→`CODEX_API_KEY` / `OPENAI_API_KEY` or `~/.codex` login | multi-provider keys / `~/.local/share/opencode/auth.json` | provider key / `AuthStorage`+`agentDir` (`~/.pi/agent/auth.json`) |
| **Agentic-edit model** | native tools `Read/Write/Edit/Glob/Grep/Bash`, `cwd` | `workspace-write` sandbox, `workingDirectory` | server-resolved `directory`; built-in edit tools | built-in `read/write/edit/bash/grep/find/ls`, `cwd`, `createCodingTools` |
| **Structured output** | `outputFormat:{json_schema}` → `result.structured_output` | `TurnOptions.outputSchema` → `JSON.parse(turn.finalResponse)` | **v2** `body.format:{json_schema,retryCount}` → `result.structured` | **none** — prompt-and-parse fenced-JSON + nudge-retry |
| **Env-control mechanism** | `options.env` replace (verified) — boundary is the SDK's own child | `CodexOptions.env` (no-inherit, verified) — **must always pass** | self-spawn `serve` w/ allowlist env | own subprocess w/ allowlist env + scrubbed `PI_CODING_AGENT_DIR` |
| **Tool/permission control** | `canUseTool` per-tool veto + `permissionMode` | **coarse** sandbox + `approvalPolicy:'never'` (no per-tool veto) | config `permission` allow/deny (avoid `ask`); event hook | `tools`/`excludeTools`/`createCodingTools`; event-bus hook |
| **Model/provider** | Claude models (per-call `model` string) | OpenAI/Codex (`model` string + `modelReasoningEffort`; tier ids verified in step 7) | `provider/model` per prompt | any of 40+ providers (`--provider`/`--model`) |
| **Usage/cost** | `total_cost_usd` + `usage` (**costUsd=yes, nativeBudget=yes** via `maxBudgetUsd`) | token-only `Usage` (**costUsd=no**; `pricing.ts`) | `tokens` + `cost` (**costUsd=yes**) | per-message `usage.cost.total` summed (**costUsd=yes**) |
| **Transcript** | terminal `SDKResultMessage`; stream events to log | `runStreamed()` `ThreadEvent`s → log | v2 `event` SSE → log | `--mode json` JSON-per-line `AgentSessionEvent` stream → log |
| **Resume** | `resume=sessionUUID` | `resumeThread(id)` (`~/.codex/sessions`) | session id | `--session` / SDK session |
| **`caps`** | `{nativeSchema:T, perToolHook:T, envIsolation:'explicit-no-inherit', costUsd:T, nativeBudget:T, resume:T}` | `{nativeSchema:T, perToolHook:F, envIsolation:'explicit-no-inherit', costUsd:F, nativeBudget:F, resume:T}` | `{nativeSchema:T(v2), perToolHook:F(event), envIsolation:'subprocess-allowlist', costUsd:T, nativeBudget:F, resume:T}` | `{nativeSchema:F, perToolHook:F(event), envIsolation:'subprocess-allowlist', costUsd:T, nativeBudget:F, resume:T}` |
| **Outlier needing `start()/stop()`** | no | no | **yes** (server lifecycle) | no |

A runner that cannot satisfy a parity line (e.g. codex's no per-tool veto, pi's no native schema) is
**documented in this matrix, not silently broken**.

---

## 6. Phase-by-phase mapping

Tiers verified at `adw/_phases.py:55-71`. Per-runner model IDs in `models.ts`; override precedence
preserved: `--model` > `MX_AGENT_MODEL_<PHASE>` env > tier default. Example tier→model (claude):
capable=`claude-opus-4-8`, mid=`claude-sonnet-4-6`, cheap=`claude-haiku-4-5`. Codex tier ids verified in
step 7: cheap `gpt-5.4-mini` / mid `gpt-5.4` / capable `gpt-5.5` (effort low/medium/high/xhigh);
opencode = `provider/model`; pi = any provider.

| Phase | Driver | Tier | Structured output | Usage/cost | Notes |
|---|---|---|---|---|---|
| **classify** | **shared `structuredCall`** (`@anthropic-ai/sdk`, **not** the selected runner) | cheap / `claude-haiku-4-5` | `messages.parse` + `zodOutputFormat(ClassifySchema)` → `parsed_output` | `response.usage` (input/output/cache); cost from `pricing.ts` | opt-out `MX_AGENT_CLASSIFY_ON_RUNNER=1` runs it on the selected runner; haiku needs no `effort`/`thinking` |
| **plan** | selected runner `runPhase` | capable | native schema (claude/codex/opencode-v2) or fenced-JSON+nudge (pi) → `PlanResult` | per-runner (see matrix) | edits tree, writes spec |
| **implement** | selected runner `runPhase` | capable | → `ImplementResult` | per-runner | edits tree |
| **tests** | selected runner `runPhase` | mid | → `TestsResult` | per-runner | edits tree |
| **resolve** (loop) | selected runner `runPhase` | mid | → `ResolveResult` | per-runner | re-invoked on red test gate |
| **e2e** (conditional) | selected runner `runPhase` | mid | → `E2EResult` | per-runner | gated by `gate_e2e` |
| **review** (artifact) | selected runner `runPhase` | capable | → `ReviewResult` (`findings[]`); free-form to files | per-runner | **agentic** — reads tree, writes `commit_message.txt`/`pr_body.md` |
| **patch** (loop) | selected runner `runPhase` | capable | → `PatchResult` | per-runner | re-invoked on blocker findings |
| **document** (conditional, artifact) | selected runner `runPhase` | mid | → `DocumentResult`; artifacts to files | per-runner | gated by `gate_document` |

**Why classify is the only single-structured phase:** its template (`.pi/prompts/classify.md`,
`OUTPUT_CONTRACT['classify']`, `adw/_phases.py:397`) says "Do not examine the codebase. Decide only from
the context above" — no repo read, no file write, no tools → a 1:1 fit for `messages.parse` + a Zod
schema. `review` *looks* structured but reads the diff and writes workspace files, so it is agentic.

**Cost / budget gating (per-runner native first):**

- `claude` uses native `maxBudgetUsd` (forwarded via `PhaseRequest.maxBudgetUsd`); a hit returns
  `error_max_budget_usd` → `PhaseResult.signal:'budget'` (fail fast, no nudge). Cost = `total_cost_usd`.
- `opencode`/`pi` report cost natively (`cost` / `SessionStats.cost`); no parent price table needed.
- **`pricing.ts` is the fallback for token-only backends only** — `codex` (`Usage`) and the `anthropic`
  classify call (`response.usage`). A stale/missing entry yields `null` cost (non-fatal) and disables the
  *parent-side* budget gate for that backend only.

**Python-only phases (no agent; reimplemented as TS control-plane code, unchanged semantics):**

| Phase | TS function | What it does |
|---|---|---|
| **setup** | `setup` | fetch issue ctx, `createOrCheckoutBranch`, status (`adw/_orchestrator.py:378`) |
| **resolve_loop** | `resolveLoop` | run test gate, re-invoke `resolve` ≤ max_attempts, truncate output into prompt |
| **patch_loop** | `patchLoop` | filter blocker findings, re-invoke `patch` ≤ max_attempts, stop on no progress |
| **ci-fix** | `ciFixLoop` | poll `ciStatus`, re-invoke `resolve` on red, reset budget after commits, settle no-checks |
| **finalize/merge** | `finalizeAndMerge` | finalize gates, commit/push/create-PR/watch-CI, `confirmMerge`, `squashMerge` |
| **report** | `postProgress` | run-tagged gh comments, never secrets (`adw/_exec.py:71-88`) |

Bounded loops stay as TS control-plane logic; a phase failure (`rc != 0`, native-schema-retry exhaustion,
or a synthetic timeout/budget rc) feeds the existing loops exactly as a failed CLI run does today.

---

## 7. Structured output & prompt composition in TS

### Per-phase Zod schemas (replacing Pydantic)

- Port each result dataclass to a **Zod schema** in `schemas.ts`: `ClassifySchema`, `PlanResult`,
  `ImplementResult`, `TestsResult`, `ResolveResult`, `E2EResult`, `ReviewFinding`/`ReviewResult`,
  `PatchResult`, `DocumentResult` — fields exactly per `OUTPUT_CONTRACT`/`to_result`
  (`adw/_phases.py:397-410`). `ClassifySchema = z.object({ issue_class: z.enum([...7 classes]), reason: z.string() })`.
- Convert Zod → JSON Schema with zod v4's native `z.toJSONSchema()` (the scaffold pins `zod@^4`,
  which `@anthropic-ai/sdk` peer-accepts, making the planned `zod-to-json-schema` dep unnecessary)
  once, per phase, shared across all runners. **Always validate in the parent with Zod** (defense
  in depth) regardless of whether the backend claims native schema output.

### Native structured output per backend, with a shared fenced-JSON fallback

| Backend | How structured output is requested → read | Fallback |
|---|---|---|
| `classify` (shared) | `messages.parse({ output_config:{ format: zodOutputFormat(ClassifySchema) }})` → `parsed_output` (null on refusal/truncation — **guard it**) | one nudge-retry (or bump `max_tokens`) then `AdwError` |
| `claude` | `options.outputFormat:{type:'json_schema',schema}` → `result.structured_output` | invoker fenced-JSON + 1 nudge |
| `codex` | `TurnOptions.outputSchema` → `JSON.parse(turn.finalResponse)` (string) | invoker fenced-JSON + 1 nudge |
| `opencode` (**v2 client**) | `session.prompt({...,format:{type:'json_schema',schema,retryCount}})` → `result.structured` (`StructuredOutputError` on exhaustion) | invoker fenced-JSON + 1 nudge |
| `pi` | **none** — accumulate assistant text from the `--mode json` line stream (the event bus on stdout), keep the trailing-fenced-JSON contract | invoker fenced-JSON + 1 nudge (this *is* pi's primary path) |

`opencode` native schema is **only** available via `@opencode-ai/sdk/v2` (`OutputFormatJsonSchema`,
`structured?`); the v1 default export has no `format`/`structured`. The adapter therefore imports the v2
client (Section 4.3-3); a **roadmap step-8 [VERIFY] gate** asserts the v2 prompt route returns
`.structured` against the pinned version before `caps.nativeSchema:true` is trusted (else opencode falls
back to the same fenced-JSON+nudge path as pi).

The fenced-JSON extraction + **one** nudge-retry (port `_NUDGE` and `parse_json` semantics from
`adw/_phases.py:472`/`adw/common.py` verbatim) is implemented **once in the invoker layer** over
`runPhase`, never duplicated per backend. Where `caps.nativeSchema` is true and the backend returns
conforming output, the fallback never fires; a native-schema backend returning a non-conforming/`null`
payload triggers the same single nudge.

### Output-contract footer: gated off for native-schema backends

The fenced-JSON output-contract footer (`buildFooter`'s "end your reply with EXACTLY one fenced json
block", `adw/_phases.py:428-451`) exists solely for stdout parsing. `composePhasePrompt` takes an
`emitJsonContract` flag: **off** when `caps.nativeSchema` is true (so the footer and `outputFormat` are
never both active), **on** for the pi path (and for opencode iff the step-8 gate fails). Artifact-file
instructions (commit_message/pr_body) are independent and stay on both paths.

### No-retry-on-timeout (and native budget), force-killed by the parent

The orchestrator owns one `AbortController` per phase with the phase timeout; `signal` is passed into
every backend (codex `TurnOptions.signal`, claude `abortController`, opencode request abort + server
kill, pi AbortSignal/owned-subprocess kill). When the signal fires the adapter returns
`PhaseResult.signal:'timeout'`. The invoker maps that to the same fail-fast as today's
`_TIMEOUT_EXIT_CODES` (`adw/_phases.py:479,512-513`): on `signal==='timeout'` it raises `AdwError`
**without** the nudge-retry; only a parse failure on a non-timed-out run triggers the single nudge. The
same fail-fast applies to claude's native `error_max_budget_usd` → `signal:'budget'`. This preserves the
verified AS-IS behavior (`adw/_phases.py:482-516`).

### Prompt composition & templates (reused verbatim)

- Reimplement `composePhasePrompt()`: `[PHASE_PREAMBLE_SHARED + PHASE_CONTEXT.get(phase)] + "---" +
  renderPromptFile(tpath, args) + "---" + buildFooter(phase, state, emitJsonContract)`. Only the
  capability-gated footer changes; everything else is identical (`adw/_phases.py:465`).
- Templates are **shared, not copied** (D4): `templatePath()` still prefers `.claude/commands/{name}.md`
  (claude runner) else `.pi/prompts/{name}.md` (14 basenames each, verified). `prompt.txt` is still
  written under `agents/{adw_id}/{phase}/` for resume.
- `PHASE_PREAMBLE_SHARED` (`adw/_phases.py:371-396`) is unchanged and remains the prompt-level half of the
  D5 boundary (Section 4.4).

### Artifact files (commit_message.txt / pr_body.md)

`review` and `document` (the `ARTIFACT_PHASES`, `adw/_phases.py:413`) still author free-form text to
workspace files via the selected runner's granted file tools (`cwd`=worktree). The parent absorbs them
post-phase (mirroring `_absorb_authored_text`, `adw/_orchestrator.py:357`) into
`state.commit_message`/`state.pr_body`; the structured envelope just signals
`wrote_commit_message`/`wrote_pr_body`.

---

## 8. State / resume & coexistence (per D4)

### `agents/{adw_id}/` convention = the cross-language contract

- The TS `adw_sdlc` writes the **same** `state.json` schema and per-phase layout
  (`prompt.txt`/`transcript.log`/`commit_message.txt`/`pr_body.md`), verified at `adw/_state.py:51-90`,
  so a run from either engine is inspectable/resumable by existing tooling.
- **v1 fields (canonical, immutable):** `adw_id, issue_number, issue_class, branch_name, base, plan_file,
  pr_number, pr_url, commit_message, pr_body, review_findings[], completed_phases[]`
  (`adw/_state.py:51-67`).
- **First cutover PR (Python-only, tiny):** add `schema_version` (int, default 1) to both the Python
  reader/writer and `adw/state.schema.json`. Land it isolated with its own test; confirm the Python
  `adw/` suite stays green.
- **TS additions are additive-only:** `total_cost_usd`, per-phase `usage`, `session_id`/`thread_id`,
  `runner`, `engine`. Python's `load()` filters to declared fields and silently drops unknown keys
  (`adw/_state.py:120-143`), so they never break `adw/`. They must **not** be load-bearing for any Python
  codepath; Python resume must remain functional from v1 fields + `completed_phases` alone.
- **Schema drift guard:** `adw/state.schema.json` is checked by **both** a Python test and a TS
  (Zod/vitest) test in CI — the only mechanism that stops two reimplementations sharing no code from
  drifting silently.

### Templates shared verbatim

`.pi/prompts/*.md` and `.claude/commands/*.md` stay the runner-agnostic source for both pipelines (14
identical basenames today; `templatePath()` selects the runner-appropriate copy). No template fork during
coexistence; runner-specific divergence is allowed later only via additive runner subdirs.

### Engine/runner selection & cutover

- `MX_AGENT_ENGINE={py|ts}` (default `py`) picks the language, **orthogonal** to `MX_AGENT_RUNNER`
  (extended to `{claude|pi|codex|opencode}`, honored only by the `ts` engine). The `py` engine ignores
  runner values it doesn't know. Validate unknown values the same way (`raise`/throw), mirroring
  `adw/_orchestrator.py:557-559`.
- **Resume across languages:** TS-only ids (codex thread, opencode session, pi session) stay additive and
  engine-private; Python resume never depends on them. `state.json` is the source of truth; `sessionId`
  is best-effort.

### Cutover criteria (all must hold; per-runner cutover is independent)

1. The Section 10 parity checklist passes for the `ts` engine with **at least the `claude` runner**.
2. **State equivalence:** a real issue run under `ts` produces `state.json` that (i) validates against
   `state.schema.json`, (ii) is loadable+resumable by Python `adw/` and vice-versa, (iii) matches the
   Python run's v1 fields modulo additive keys — asserted by an automated cross-language fixture test.
3. Templates remain byte-identical and shared (drift test green).
4. **Secret-withholding proven per shipped runner:** an automated test asserts `GH_TOKEN`/`MATRIX_*`/
   `MX_AGENT_*` are absent from each runner child's **observable spawned env** (the env the SDK actually
   passes to the child for claude/codex; the spawn env for opencode/pi) — for codex specifically,
   asserted *after* the SDK builds the child env (so an `apiKey`-routed key cannot slip past).
5. The squash-merge stays gated behind explicit confirmation in the TS path.
6. The Python `adw/` suite stays green unchanged (only delta allowed pre-cutover: additive
   `schema_version`).

Flip `MX_AGENT_ENGINE` default `py → ts` when 1–6 hold for `claude`. A runner ships only when its
capability-matrix row is satisfied or its phase falls back to the shared `structuredCall` (classify) /
another runner. Do **not** delete Python `adw/` at cutover; keep it ≥1 stable release, then remove in a
separate cleanup PR.

---

## 9. Dependency boundary & toolchain (per D3)

- **Runtime:** Node LTS (`engines >=20.19`, the locked toolchain's floor — vite 8 under vitest 4
  requires `^20.19.0 || >=22.12.0`; CI matrix 20 + 22), **not** Bun/Deno. Note the pinned
  `@earendil-works/pi-coding-agent` declares `node >=22.19`, so the Node-20 lane exercises only
  the claude/codex/opencode adapters once runners land. ESM-only
  (`"type":"module"`, `moduleResolution nodenext`, `target ES2022`).
- **Package manager:** **pnpm** (committed `pnpm-lock.yaml`, `pnpm-workspace.yaml` member `adw_sdlc/`);
  `--frozen-lockfile` in CI. (npm is a viable fallback if the team prefers zero new tooling.)
- **Non-optional runtime deps:** `@anthropic-ai/sdk` (`^0.104.1`, classify single-structured call) and
  `zod` (`^4`, validation; zod v4's native `z.toJSONSchema()` replaces the originally planned
  `zod-to-json-schema`).
- **`optionalDependencies` (the four runner SDKs):** `@anthropic-ai/claude-agent-sdk` (`^0.3.170`),
  `@openai/codex-sdk` (`0.139.0`, **exact**, lockstep with `@openai/codex`), `@opencode-ai/sdk`
  (`^1.17.3`, used via the **`@opencode-ai/sdk/v2`** subpath where native schema is required),
  `@earendil-works/pi-coding-agent` (npm resolves `0.79.1`). Each adapter is reached **only** through
  `await import()` inside `registry.ts`; a missing SDK surfaces as a typed "runner not installed"
  `AdwError`, not a module-load crash. The committed lockfile is the hard pin; codex SDK + binary
  versions must match (CI assertion).
- **Build/run:** `tsc -p tsconfig.build.json` for the authoritative typecheck gate (mirrors
  `cargo clippy -D warnings`); `tsx` for dev/CI run. `tsup` is a one-line later add if a distributable
  CLI bundle is ever needed.
- **Tests:** **vitest** (native TS/ESM, first-class `vi.mock` for stubbing the four heavy SDKs, built-in
  coverage).
- **Static gates (security/regression):** a lint/grep gate fails CI on `...process.env` inside any
  `src/runners/*.ts`, and a unit/lint check asserts the codex adapter constructs/calls the SDK only with
  an explicit `env` arg (omission flips codex to full-inherit, `@openai/codex-sdk` 0.139.0
  `dist/index.js:234-239`).
- **CI:** add an `adw_sdlc` job (sibling to the untouched Python `adw` job): `setup-node` (matrix 20+22)
  + `pnpm/action-setup`; `pnpm install --frozen-lockfile`; `pnpm run typecheck` (`tsc --noEmit`);
  `pnpm run test` (`vitest run`). It runs with **no network, no API keys, no native binaries** — every
  SDK is replaced by `vi.mock` stubs returning canned `PhaseResult`/structured/usage fixtures. An opt-in,
  `workflow_dispatch`, secrets-gated integration lane (not a required check) runs one phase per runner
  against the real SDKs.

---

## 10. Test strategy & parity checklist

### Seams to mock per backend

- **Mock the `AgentRunner` interface, not the SDK**, for orchestrator/parity tests (mirrors how
  `run_agent_phase` is mocked today, `adw/test_orchestrator.py`, `adw/test_phases.py`). The
  orchestrator/parity tests stay runner-agnostic: same git/state/gh mocks as `adw/`. `runner-mock.ts`
  provides a scriptable runner.
- **Per-adapter unit tests** mock each SDK via `vi.mock`: claude `query` → scripted `SDKResultMessage`
  (`structured_output`, `total_cost_usd`, `usage`); codex `thread.run` → `Turn{finalResponse,usage}`;
  opencode **v2** `session.prompt` → `{structured, tokens, cost}`; pi `createAgentSession` → scripted
  `AgentSessionEvent`s + `SessionStats.cost`. Assert request shape (model ID, schema, `cwd`, **`env`
  allowlist**, tool grants/sandbox, permission config).
- **Env-isolation test (highest severity):** with a **poisoned** parent env (`GH_TOKEN=x`,
  `MATRIX_TOKEN=x`, `MX_AGENT_FOO=x`), assert the env the SDK/spawn actually hands the child contains only
  the per-runner allowlist and **never** `GH_TOKEN`/`MATRIX_*`/`MX_AGENT_*`. For claude/codex assert on
  the **`options.env`/`CodexOptions.env` object the SDK passes to the child** (for codex, after the SDK
  builds it, so an `apiKey`-routed key is caught); for opencode/pi assert on the spawn env. Add a
  lint/grep gate against `...process.env` in runner modules (Section 9).
- **Tool-grant test:** assert each editing phase grants file/edit capability with `cwd=worktree` and an
  unattended-edits mode (claude `acceptEdits`/`canUseTool`; codex `workspace-write`+`never`; opencode
  `permission:allow`; pi tools), and that claude's `canUseTool` denies git/gh.
- **Codex always-passes-env test:** assert the codex adapter never constructs `new Codex(...)` /
  `thread.run(...)` without an explicit `env` (regression guard; omission flips codex to full-inherit).

### Parity checklist (all must hold before flipping default to `ts`, for the shipped runner)

- [ ] **Phase order & gating:** all 9 agent phases + setup/finalize/ci-fix/merge/report run in the same
      order; conditional `e2e`/`document` gates fire identically (`gate_e2e`/`gate_document`,
      `adw/_phases.py:165-188`).
- [ ] **Per-phase model routing:** each phase uses the exact pinned ID for its tier (per-runner registry);
      override precedence (`--model` > `MX_AGENT_MODEL_<PHASE>` > tier) honored.
- [ ] **Selected runner can edit the working tree unattended (capability parity):** file/edit capability
      with `cwd=worktree` and an edits-allowed mode (or the phase is the structured-only `classify`).
- [ ] **Structured output:** every phase yields a Zod-validated result; hard-failure rate (incl.
      `error_max_structured_output_retries`/`StructuredOutputError`/null `parsed_output`) is **no worse**
      than the fenced-JSON+nudge path over the parity runs.
- [ ] **Secret withholding (fail-closed) — load-bearing, per runner:** the runner child's **observable
      spawned env** excludes `GH_TOKEN`/`MATRIX_*`/`MX_AGENT_*` (env-isolation test, asserted on the env
      the SDK hands the child for claude/codex); a newly-added parent secret is absent by default, so the
      agent's git/gh fail closed.
- [ ] **Sandboxed-to-worktree (per runner):** the runner is sandboxed/cwd-bound to the worktree (codex
      `workspace-write`; opencode server cwd; claude/pi `cwd`). Per-tool veto only where
      `caps.perToolHook` (claude) — documented in the matrix, not assumed universal.
- [ ] **Gated squash-merge:** the TS `confirmMerge` refuses unattended without `--yes`/`MX_AGENT_YES=1`.
- [ ] **Bounded loops + no-retry-on-timeout:** `resolveLoop`/`patchLoop`/`ciFixLoop` cap attempts and
      stop on no-progress identically; a phase that times out yields `signal:'timeout'` (and claude's
      native budget hit yields `signal:'budget'`) mapped to a synthetic `_TIMEOUT_EXIT_CODES` rc that
      fails fast with **no** nudge.
- [ ] **Resume:** `--adw-id --resume` skips done phases, reconstructs review findings for patch,
      short-circuits after merge; produces equivalent `state.json`.
- [ ] **Artifacts:** `review`/`document` write `commit_message.txt`/`pr_body.md`, absorbed into state.
- [ ] **State equivalence (cross-language):** `state.json` validates against `state.schema.json` and is
      loadable+resumable by Python `adw/` and vice-versa (machine-checkable parity assertion).
- [ ] **Cost/usage:** `total_cost_usd`/`usage` recorded per phase — **native** for claude/opencode/pi,
      parent-computed from `pricing.ts` for token-only backends (codex, anthropic classify); claude's
      native `maxBudgetUsd` gate is honored, with the parent price-table gate only for token-only backends.
- [ ] **adw/ green:** the unchanged Python `adw` test suite stays green throughout.

---

## 11. Incremental implementation roadmap

Each step is small, independently verifiable, and leaves both Python `adw/` green and the deployed engine
unchanged until cutover. **Recommended first runner: `claude`** — closest API match (verified reference
shape: `query()` + `outputFormat:json_schema` + `structured_output`/`total_cost_usd`), native file tools,
native budget gating (`maxBudgetUsd`), and the cleanest secret-withholding story (the SDK already spawns a
child and `options.env` replaces `process.env` — **no bespoke fork**). Order thereafter: **codex** (best
env-withholding fit, schema output), **opencode** (richest structured/usage but needs the v2 client +
self-spawned-server wrapper), **pi** (in-process SDK; no native schema → fenced-JSON path).

1. **Phase 0 — `schema_version` + `state.schema.json` (Python only).** Add the additive field to both
   sides + the cross-language contract test. **Verify:** Python `adw/` suite green; schema test passes.
2. **Scaffold the TS package (D3).** `package.json` (ESM, engines, optionalDeps), `tsconfig*.json`,
   `pnpm-workspace.yaml`, committed `pnpm-lock.yaml`, the mocked `adw_sdlc` CI job + the `...process.env`
   lint/grep gate. **Verify:** `pnpm install --frozen-lockfile` + `pnpm run typecheck` + empty
   `vitest run` pass; the `adw` job untouched and green.
3. **Define `AgentRunner`/`PhaseRequest`/`PhaseResult`/`RunnerCaps` (`invoker.ts`) + the registry
   skeleton (`registry.ts`, dynamic import).** **Verify:** typecheck; registry raises a typed
   "runner not installed" error for an absent optional SDK.
4. **Zod schemas (`schemas.ts`) for all result types + `models.ts` tier→model maps + `pricing.ts`
   (token-only backends).** One smoke test that `zodToJsonSchema` round-trips and matches
   `OUTPUT_CONTRACT` fields. **Verify:** schemas validate fixtures.
5. **Control plane (`orchestrator.ts`, `state.ts`, `git.ts`, `env.ts`) + the structured-call classify
   helper (`structured-call.ts`) on `@anthropic-ai/sdk`, driven by `runner-mock.ts`.** Parity-test the
   state machine, bounded loops, gates, no-retry-on-timeout, and the env-allowlist builder under mocks
   (no real agent). **Verify:** orchestrator parity tests green; env-isolation test green;
   `safeSubprocessEnv` excludes `GH_TOKEN`/`MATRIX_*`/`MX_AGENT_*`.
   *Landed notes:* the port added the Python-analogue modules `common.ts`/`exec.ts`/`issue.ts` and split
   the nudge/timeout invoker logic into `run-phase.ts` (invoker.ts stays types-only); external effects
   are injected via an explicit `OrchestratorDeps` object (the TS analogue of the module seams the
   Python tests patch) rather than module patching; `resolve_runner_bin` was deliberately not ported —
   binary resolution is per-adapter and lands with each runner (steps 6–9).
6. **Runner #1 = `claude` (`runner-claude.ts`).** `query({prompt, options:{model, cwd, env: allowlist,
   pathToClaudeCodeExecutable: resolvedBin, allowedTools, permissionMode:'acceptEdits',
   outputFormat:{json_schema}, maxBudgetUsd, abortController}})`; read terminal `SDKResultMessage`
   (`structured_output`/`total_cost_usd`/`usage`); map `error_max_budget_usd` → `signal:'budget'`. **No
   forked child** — `options.env` is the boundary (verified replace-semantics). **Resolved (no longer
   [VERIFY], confirmed on the installed `sdk.d.ts` 0.3.173):** env replace-vs-merge (replace), SDK spawns
   a child, PATH-on-allowlist for `pathToClaudeCodeExecutable`/`executable` location; `CanUseTool =
   (toolName, input, {signal, toolUseID, ...}) => Promise<PermissionResult>` with `PermissionResult` the
   allow/deny union (`updatedInput?` / `message`); `PermissionMode = 'default'|'acceptEdits'|
   'bypassPermissions'|'plan'|'dontAsk'|'auto'` (`acceptEdits` exists as planned); there is **no**
   `maxStructuredOutputRetries` option — schema-retry exhaustion surfaces only as the result subtype
   `error_max_structured_output_retries`, which the adapter maps to a failed `PhaseResult` with
   `signal:'none'` so the invoker's single nudge applies. **Verify:** mocked-`query` unit tests (request
   shape incl. tool grants + `env`, result mapping); env-isolation (assert `options.env`) + tool-grant
   tests; live smoke on one phase.
   *Landed notes:* `canUseTool` denies Bash git/gh at a command position (best-effort; GH_TOKEN absence
   stays the load-bearing control), allows non-git/gh Bash, and fails closed on tools outside the grant;
   **Bash is excluded from `allowedTools`** because an allow rule resolves before `canUseTool` — with
   Bash listed, the veto is dead code (adversarial review caught this; the corrected wiring is verified
   by a live probe: git denied with the veto's message, benign Bash allowed). Binary resolution ports
   `adw/_exec.py:201-213` but reads the ALLOWLIST env and returns undefined instead of raising when
   nothing resolves (the SDK then uses its built-in executable); a non-abort SDK throw maps to a failed
   `PhaseResult` (rc 1, output kept) mirroring a crashed CLI run, never an exception, so the bounded
   loops see it exactly as today. An abort that lands after the terminal result still passes
   `structured_output` through (signal stays 'timeout'/'cancelled'; the invoker owns the parse-first
   policy); SDK `errors[]` are teed to the transcript file (file only — transcriptText stays
   assistant-text-only so the trailing-fenced-JSON fallback keeps parsing); the invoker's timeout abort
   reason is the shared `PHASE_TIMEOUT_ABORT_REASON` constant (invoker.ts). Live smoke verified: native
   `structured_output`, `total_cost_usd`, `session_id`, transcript tee.
7. **Runner #2 = `codex` (`runner-codex.ts`).** `new Codex({env: allowlist, apiKey})` →
   `startThread({model, modelReasoningEffort, workingDirectory, sandboxMode:'workspace-write',
   approvalPolicy:'never', skipGitRepoCheck:true})` → `thread.run(prompt, {outputSchema, signal})`;
   `JSON.parse(turn.finalResponse)`; compute `costUsd` from `pricing.ts`. **Always pass `env`** (test +
   lint gate). **[VERIFY] steps:** current `-codex` model ids for the tiers; minimal env for
   ChatGPT-login mode (HOME); native binary install/preflight; outputSchema JSON-only robustness.
   **Verify:** env-no-inherit asserted **on the SDK-built child env** (catches `apiKey`-routed keys);
   coarse permission limit recorded in `caps`; always-passes-env test.
   *Landed notes — [VERIFY] resolutions:* tier ids `gpt-5.4-mini`/`gpt-5.4`/`gpt-5.5` confirmed
   current (Codex models endpoint cache of 2026-05-31, all `supported_in_api`, effort
   low|medium|high|xhigh; the `-codex` suffix is gone — the last suffixed model is `gpt-5.3-codex`)
   and priced in `pricing.ts` from the OpenAI pricing docs ($0.75/$4.50, $2.50/$15, $5/$30 per MTok,
   cache read 0.1×, no cache-write charge). ChatGPT-login mode needs only `HOME` (auth.json under
   `~/.codex`; `CODEX_HOME` is allowlisted so callers can point it at a scrubbed dir — the Section
   4.4 residual-surface mitigation); API-key mode rides `CODEX_API_KEY`/`OPENAI_API_KEY` on the
   allowlist, and the SDK `apiKey` option is deliberately **unused** (it injects `CODEX_API_KEY`
   into the child env *after* the env override is applied, routing a credential around the
   allowlist). Binary preflight: the `Codex` constructor resolves the lockstep vendored binary and
   throws when the platform package is absent — constructed inside `runPhase`'s try, so it surfaces
   as a failed `PhaseResult` (crashed-CLI parity), never an exception out of the seam. `CODEX_BIN`
   (allowlist) overrides the binary; there is deliberately **no PATH search** — a PATH `codex` can
   be any version and would silently break the SDK↔binary lockstep pin. `outputSchema` JSON-only
   output is documented (`AgentMessageItem.text`: "JSON when structured output is requested") but
   not contractual → the adapter `JSON.parse`s defensively and the invoker fenced-JSON
   fallback + single nudge own non-conforming replies. Codex token counts are OpenAI-API-shaped
   (`input_tokens` *includes* `cached_input_tokens`; `output_tokens` *includes*
   `reasoning_output_tokens`) and are remapped to the disjoint `PhaseUsage` convention before
   `pricing.ts` prices them. The secret-withholding test asserts on the **SDK-built child env** by
   driving the real 0.139.0 SDK over a mocked `child_process.spawn`
   (`runner-codex-spawn.test.ts`; the SDK is inlined in vitest so the mock applies inside it),
   alongside the mocked-SDK always-passes-env test and a `new Codex(` must-pass-env tripwire in
   `scripts/check-adw-sdlc-env.sh`. Live smoke: the vendored binary spawned and streamed JSONL
   through the adapter end-to-end (thread-id capture + `turn.failed`→failed-result mapping verified
   live), but the phase itself was blocked by a stale ChatGPT refresh token on the dev machine
   ("refresh token was already used") — **re-run one live phase after `codex login` before trusting
   the runner on a real issue.**
8. **Runner #3 = `opencode` (`runner-opencode.ts`).** `start()` self-spawns
   `opencode serve --port N` with `{cwd, env: allowlist}`, scrape readiness banner, connect the **v2
   client** (`@opencode-ai/sdk/v2`); `session.create` → `session.prompt({...,format:{json_schema,retryCount}})`;
   read `tokens`/`cost`/`structured`; tee v2 `event` to transcript; `stop()` kills the server.
   **[VERIFY] gate (blocks `nativeSchema:true`):** the **v2** prompt route returns `.structured` against
   the pinned `^1.17.3`; if not, downgrade opencode to `caps.nativeSchema:false` and route through the
   fenced-JSON+nudge path. **Other [VERIFY] steps:** readiness banner string; canonical structured
   accessor; per-request `?directory=`/`x-opencode-directory` honored on the v2 prompt route. **Verify:**
   self-spawn env-absence test; server start/readiness/teardown + port-collision handling.
   *Landed notes — [VERIFY] resolutions (installed 1.17.3 `.d.ts`/`.js` + a live gate against the real
   1.17.3 binary driven through a local OpenAI-compatible stub provider, so no credential was needed):*
   the **v2 prompt route returns `.structured`** (`AssistantMessage.structured`), so
   `caps.nativeSchema:true` stands — mechanically the server exposes a **`StructuredOutput` tool whose
   parameters ARE the schema** (`tool_choice:'required'`) and validates the model's call, with
   `StructuredOutputError` surfacing on `info.error` after `retryCount` exhaustion (mapped to a failed
   result, `signal:'none'`, so the invoker's single nudge applies). Readiness banner is
   `opencode server listening on <url>` (the same line the SDK's own wrapper scrapes; accepted from
   stdout or stderr). **`--port 0` is NOT an ephemeral bind** — it silently falls back to the default
   4096 (observed live) — so the adapter draws a random IANA dynamic-range port and retries
   exit-before-banner up to 3 times (the observable symptom of a collision); spawn errors and banner
   timeouts fail immediately. `directory` rides the prompt/create POSTs as an explicit **query param**
   in the generated v2 client (the GET/HEAD-only header-rewrite interceptor is not involved) and is
   honored live (`session.directory`/`info.path.cwd` = the request dir, macOS-realpath-canonicalized).
   Config injection uses **`OPENCODE_CONFIG_CONTENT`** on the spawn env (the channel the SDK wrapper
   uses) carrying the permission ruleset `{'*':'allow', bash:{'git *':'deny','gh *':'deny','*':'allow'}}`
   — never `'ask'` (hangs headless); project `opencode.json` still merges (the live stub provider was
   configured that way). **Deviation from the step sketch:** the server starts lazily on the FIRST
   `runPhase`, not in `start()` — the registry's `createRunner()` contract provides no env/cwd at
   construction, and they only arrive with the first `PhaseRequest`; `start()` is an interface-parity
   no-op, `stop()` remains the teardown seam, and `orchestrator.run()` now calls
   `await runner.start?.()` before the phase loop and `await runner.stop?.()` in a `finally` (mock-run
   lifecycle test). One server per run (keyed to the first request), one session per phase
   (`sessionId` = resume handle). The SSE tee (`client.event.subscribe`) streams **assistant-only**
   text deltas/updates live (the bus replays the USER message's parts too, observed live — filtered by
   tracking assistant message ids from `message.updated`), tool terminal states as file-only notes,
   deduped against the authoritative final-parts replay by written-length tracking, so transcriptText
   stays assistant-text-only for the fenced-JSON fallback. The SDK's `createOpencodeServer`/
   `createOpencode(Tui)` spread the parent process env onto the child (verified on `dist/v2/server.js`)
   and are banned by a fail-closed gate in `scripts/check-adw-sdlc-env.sh` (call/import/subpath
   patterns; the adapter imports `@opencode-ai/sdk/v2/client` only). `OPENCODE_BIN` overrides binary
   resolution (then PATH, then `~/.opencode/bin/opencode`); `XDG_DATA_HOME` joins the opencode
   allowlist row so callers can point the auth dir at a scrubbed location (Section 4.4 mitigation,
   CODEX_HOME parallel). Native cost (`info.cost`) and provider-shaped tokens (`tokens.input` is
   cache-disjoint for the Anthropic-style providers the tier table routes to) are finite-checked
   before use; cost degrades to `null`, never NaN.
9. **Runner #4 = `pi` (`runner-pi.ts`).** Drive `@earendil-works/pi-coding-agent` (npm resolves
   `0.79.1`) over an orchestrator-owned subprocess boundary (CLI `-p --mode json` / `--mode rpc`, or the
   in-process SDK invoked inside a child we spawn) with the allowlist env **and** `agentDir`/`authStorage`
   pointed at a scrubbed throwaway auth dir. **Output is captured via the event bus, not a return value:**
   `AgentSession.prompt()` returns `Promise<void>`; accumulate assistant text + `SessionStats.cost` from
   `subscribe()` `AgentSessionEvent`s, then apply fenced-JSON + one-nudge-retry; resume via `--session`.
   `caps.nativeSchema:false` (no `responseFormat` in `PromptOptions` — correct), `caps.costUsd:true`
   (`SessionStats.cost`). **[VERIFY] steps:** whether `--mode json/rpc` gives a cleaner stream than `-p`;
   `AuthStorage`/`agentDir` interaction with a non-inheriting env. **Verify:** env-allowlist asserted on
   the spawn; event-bus output capture matches today's fenced-JSON contract.
   *Landed notes — [VERIFY] resolutions (installed 0.79.1 dist + a live gate on the real binary driven
   through a local OpenAI-compatible stub provider via a scrubbed-agentDir `models.json`, so no
   credential was needed):* the adapter drives the **CLI's `--mode json` stream** — the same binary and
   flag mapping the Python pipeline runs today (`build_runner_command`, `adw/_runner.py:43-50`; the
   phased Python caller stays in text mode, `json_mode=False` at `adw/_phases.py:534`, so always opting
   into the json stream is the TS rewrite's deliberate upgrade) — **not** the in-process SDK inside a
   bespoke child. `--mode json` IS the
   event bus: print mode `session.subscribe()`s and writes one JSON `AgentSessionEvent` per stdout line
   (`dist/modes/print-mode.js`), preceded by the session header (`{type:'session', id, cwd}` →
   `PhaseResult.sessionId`), carrying assistant `text_delta`s, full `message_end` messages with
   per-message `usage` incl. **native dollars** (`usage.cost.total`, summed per phase),
   `stopReason`/`errorMessage`, and tool events — so `SessionStats.cost` is never needed; plain `-p`
   loses usage/cost/stopReason and `--mode rpc` is a long-lived bidirectional protocol, wrong shape for
   single-shot phases. The CLI choice also keeps the adapter **import-free**: the npm package's engines
   floor (`node >=22.19.0`) makes pnpm silently skip the optionalDependency on older Node (incl. the CI
   node-20 leg), which a static SDK type-import would turn into a typecheck break — consequently the pi
   runner can never raise `RunnerNotInstalledError`; a missing `pi` binary surfaces per-phase as a
   failed PhaseResult (crashed-CLI parity; `PI_BIN` override, then PATH, both read from the allowlist).
   `AuthStorage`/`agentDir` vs the non-inheriting env: `getAgentDir()` reads `PI_CODING_AGENT_DIR` else
   `$HOME/.pi/agent` (`dist/config.js:393-398`); keys resolve auth.json → env
   (`ANTHROPIC_API_KEY`/`OPENAI_API_KEY`, pi-ai `dist/env-api-keys.js`) → `models.json` fallback — so
   `PI_CODING_AGENT_DIR`/`PI_CODING_AGENT_SESSION_DIR` joined the pi allowlist row (Section 4.4
   mitigation, CODEX_HOME/XDG_DATA_HOME parallel; verified live: auth.json + sessions land in the
   scrubbed dir, the scrubbed HOME stays untouched). Headless quirks handled: in `--mode json` the
   process **exits 0 even when the turn failed** (the stopReason check in print-mode.js is text-mode
   only) — the adapter derives failure from the last assistant message's `stopReason`
   ('error'/'aborted' → rc 1, signal 'none', so the invoker's single nudge applies; verified live
   against a dead provider port) — and project trust resolves silently to **untrusted** headless (no
   UI, no `--approve`), which only skips project-local `.pi` settings/extensions — nothing load-bearing
   (the orchestrator inlines the full prompt) and the safer default. Abort = SIGTERM (print mode's own
   handler disposes and exits 143) with an unref'd SIGKILL escalation so a wedged child cannot hang the
   phase. transcriptText stays assistant-text-only (deltas streamed live, reconciled against the
   authoritative `message_end` text by written-length tracking; tool/stderr/non-JSON-stdout notes are
   file-only), keeping the trailing-fenced-JSON contract parseable. Token counts are finite-checked and
   cost degrades to sticky `null` on any unpriceable message, never NaN (step-7/8 lessons).
10. **Wire `MX_AGENT_ENGINE` + `MX_AGENT_RUNNER` selection.** `ts` engine binds the selected runner into
    `orchestrator.run`; unknown values throw. **Verify:** orchestrator parity tests pass under the `ts`
    engine with each shipped runner via the mock + real adapters; equivalent `state.json`.
    *Landed notes:* the selection layer is a new TS CLI (`src/cli.ts`, `pnpm run issue` /
    `tsx src/cli.ts`) so `adw/` stays untouched: `--engine`/`MX_AGENT_ENGINE` (flag wins; default `py`
    until step 12 flips `DEFAULT_ENGINE`) resolves via `resolveEngineId` — the engine twin of
    `resolveRunnerId` — and unknown values for either throw (`adw/_orchestrator.py:557-559` parity).
    `engine=py` **delegates**: spawn `python3 adw/issue.py` with this CLI's argv forwarded verbatim
    (only `--engine` is stripped; post-`--` passthru re-appended) and the FULL parent env, so the py
    engine parses its own flags, applies its own pi|claude runner validation, and builds its own secret
    boundary exactly as a direct invocation — the TS layer deliberately does **not** pre-validate the
    runner for py. `engine=ts` parses the phased flags (mirroring `adw/issue.py build_parser`, with
    env fallbacks `MX_AGENT_TEST_CMD`/`REPO`, seconds→ms conversions, and the TS-only
    `--max-budget-usd`), rejects py-only flags (`--one-shot`/`--template`/`--json`/`--print-prompt`/
    `--log-dir`/`--thinking`) and post-`--` runner passthru (the ts engine drives SDK seams; there is
    no runner command line to splice flags into — fail loud, not silent drop), then
    `resolveRunnerId(--runner ?? MX_AGENT_RUNNER)` → `registry.loadRunner` → `orchestrator.run`.
    Expected failures (AdwError incl. RunnerNotInstalledError) print `error: …` and exit 1, mirroring
    the Python `main()`. **Verify landed as two suites:** `cli.test.ts` (selection/validation/
    delegation/binding over injected seams) and `engine-parity.test.ts` — the full chain under the ts
    engine per Section 10's "mock the AgentRunner interface, not the SDK": each shipped runner's
    identity + real exported caps profile through the REAL invoker layer (the pi profile drives the
    fenced-JSON extraction path, the other three the native-schema path), state.json asserted
    equivalent across all four (modulo adw_id/runner/branch-embedded id) and schema-valid against
    `adw/state.schema.json` (validator now shared in `test/helpers/state-schema.ts`); plus the real
    claude adapter (cutover-gate runner) bound through the actual `main()` → real `registry.loadRunner`
    → `run()` path over a vi-mocked SDK, with the D5 no-secret assertion re-checked on every
    `options.env` the SDK seam received. Per-adapter transport fidelity for codex/opencode/pi stays in
    their own step-7/8/9 suites. Live smoke: default → `python3 adw/issue.py` plan (`via pi`,
    `setup(python)`); `MX_AGENT_ENGINE=ts` → TS plan (`via claude`, `setup(ts)`); unknown
    engine/runner → `error: unknown engine: 'rust' (valid: py, ts)` / `error: unknown runner:
    'gemini' (…)`, rc 1. **Adversarial-review fixes folded in (8 confirmed findings):** `-h`/`--help`
    prints usage and exits 0 on the ts engine (argparse parity; a py-engine `--help` is delegated so
    Python prints its own) — without this, plain `--help` would regress to rc 1 at the step-12
    cutover; positional tokens follow argparse `nargs='*'` semantics — ONE contiguous chunk anywhere,
    a second run fails loud (`unrecognized argument: …`, so a space-separated `--phases plan implement`
    typo cannot silently demote phases to notes); an option-looking token is never swallowed as a flag
    value (negative numbers excepted), so `--model --yes` fails loud instead of eating the user's
    `--yes`; explicit-but-empty `--engine=`/`--runner=` fail loud instead of masking the env vars and
    silently picking defaults (empty *env vars* still mean unset); `--dry-run` previews WITHOUT
    loading the optional runner SDK (py parity: the plan prints after a name-only check, via an inert
    preview runner whose `runPhase` always throws); a set `PI_THINKING` is noted as ignored on the ts
    engine rather than silently dropped (the phased Python path forwards it to the pi CLI; the
    PY_ONLY_FLAGS doc was corrected accordingly — `--thinking` is phased-relevant in py, not
    one-shot-only); the REAL `spawnPyEngine` is pinned by `cli-py-engine.test.ts` over a mocked
    `node:child_process` (command `python3` + `adw/issue.py`, `cwd=REPO_ROOT`, `stdio:'inherit'`,
    **no `env` option** so the child inherits the full parent env, exit-code passthrough, signal→1,
    spawn-error→AdwError) — the one spawn site whose contract is the deliberate inverse of the D5
    allowlist; and the py-delegation test forwards a TS-invalid runner (`gemini`) so accidental
    pre-validation on the py path cannot ship green.
11. **Parity checklist (Section 10) under mocked seams, then real-issue runs per runner.** Record
    cost/usage and structured-output hard-failure rates; assert cross-language state equivalence.
    **Verify:** all checklist boxes ticked for `claude` (cutover gate); other runners' capability-matrix
    rows green or documented.
    *Landed notes — MOCKED-SEAMS HALF DONE (PR #335, squash `fc6495d`); live real-issue runs still
    owed:* the step splits cleanly into a mocked-seams half (automatable, now landed) and a live half
    (real-issue runs per runner — credentials + spend + a human, not autonomously runnable). **Landed
    (mocked seams):** (a) the named-but-previously-unproven **cutover criterion #2** (cross-language state
    equivalence) is now an automated cross-language fixture test, tested from BOTH languages since no code
    is shared across the boundary — `adw/test_cross_language_state.py` + `adw_sdlc/test/
    cross-language-state.test.ts` each (i) schema-validate both engines' `state.json` against
    `adw/state.schema.json`, (ii) load the OTHER engine's `state.json` through their own `AdwState.load()`
    and assert the v1 fields + `completed_phases` + the blocker finding survive (the resume contract; the
    Python reader drops additive keys), and (iii) assert v1-projection equivalence modulo the TS-additive
    keys; committed golden fixtures live in `adw/fixtures/cross_language/{py,ts}-produced-state.json` (the
    shared contract dir next to `state.schema.json`) and are **byte-matched against the real writers** by a
    per-language drift guard so they cannot silently rot. (b) The Section-10 checklist + Section-8 cutover
    criteria are materialized in **`adw_sdlc/PARITY.md`**, each box mapped to its proving test, splitting
    mocked-seams evidence (complete for `claude`) from the human-gated live runs. **Clarification folded
    in:** the TS engine's realized *top-level* `state.json` additive keys are exactly
    `engine`/`runner`/`total_cost_usd` — the `session_id`/per-phase `usage` mentioned in §8's additive list
    are per-phase artifacts, not top-level state fields — so the equivalence tests target precisely those
    three. `adw/` production code stays untouched (test + fixtures only; the dual-language contract test is
    mandated by the §8 schema-drift-guard design). Gates: `pytest adw/` 192 passed; `adw-sdlc` typecheck +
    317 vitest + env-lint green. Adversarial review: 1 confirmed minor (asymmetric fixture key-set guard),
    fixed. **Still owed (live half):** one real GitHub issue end-to-end per runner recording cost +
    structured-output hard-failure rate — `claude` done (#304→#331, fix #332); **`codex` blocked** on an
    OAuth refresh token revoked server-side (unblock with `OPENAI_API_KEY`, which skips the OAuth refresh);
    `opencode`/`pi` owed (real provider key; pi also needs Node ≥ 22.19). The `claude` cutover gate
    (criteria 1–6) is met under automated tests + the completed #331 run, so **step 12 is unblocked for
    `claude` pending the maintainer's sign-off on the live evidence**.
12. **Cutover:** flip `MX_AGENT_ENGINE` default `py → ts` once the `claude` runner satisfies the cutover
    criteria (Section 8). Keep Python `adw/` as the `py` fallback engine for ≥1 stable release.
13. **Cleanup (separate PR, after one clean `ts`-default release):** remove Python `adw/` (and retire the
    fenced-JSON fallback for native-schema backends once their structured output is proven reliable).

(The cross-run memory module is **not** a roadmap step — it is deferred to a separate post-cutover
proposal; see D2/Non-goals.)

---

## 12. Risks & open questions

Every uncertain runner fact is a **[VERIFY]** roadmap step, not an assertion.

### Risks (with mitigations)

- **opencode native schema is v2-only.** The `format:{json_schema}` → `result.structured` capability
  exists **only** in `@opencode-ai/sdk/v2`; the v1 default export cannot do it. Mitigated by wiring the
  v2 client explicitly (Section 4.3-3) behind a step-8 gate that downgrades opencode to
  `caps.nativeSchema:false` (fenced-JSON path) if the v2 prompt route does not return `.structured` on
  the pin. → step 8.
- **opencode SDK leaks `process.env` / lacks cwd (`createOpencodeServer`).** Mitigated by
  **self-spawning** `opencode serve` with `{cwd, env: allowlist}` (Section 4.3-3) + an env-absence test.
  → step 8.
- **codex always-pass-env regression.** Omitting `CodexOptions.env` flips codex from no-inherit to
  full-inherit (`@openai/codex-sdk` 0.139.0 `dist/index.js:234-239`). Mitigated by an always-passes-env
  unit test + lint gate, and by asserting the secret-withholding test on the **SDK-built child env**
  (catches an `apiKey`-routed `CODEX_API_KEY` even when the env allowlist omits it). → step 7.
- **pi has no native JSON-schema output.** Only remaining pi weakness (the SDK is otherwise full-featured:
  `createAgentSession`, `AuthStorage`/`agentDir`, per-message `usage.cost`). Mitigated by the
  fenced-JSON+nudge path (exactly today's behavior) and the `--mode json` event-stream capture. → step 9
  (landed).
- **Coarse permission control on codex** (sandbox + `approvalPolicy:'never'` only; no per-tool veto).
  Recorded in `caps.perToolHook=false`; the parity line is "withholds secrets AND sandboxed", not
  "per-tool callback". → step 7.
- **Token-only cost on codex + anthropic classify.** These two backends report tokens only; opencode,
  claude, and pi report cost natively. Mitigated by a parent `pricing.ts` price table **scoped to the
  token-only backends**; a stale/missing entry yields null cost (non-fatal; degrades only the parent-side
  budget gate). → steps 4/7.
- **Native-schema backends can still emit non-conforming/null output** (codex `finalResponse` robustness,
  opencode `StructuredOutputError`, claude `structured_output` null). Mitigated by always Zod-validating
  in the parent + the single nudge-retry; two failures fail the phase (same failure mode as today).
- **codex native binary install footprint** (per-platform `@openai/codex`; offline/air-gapped unverified).
  Mitigated by mocking all SDKs in CI (no native installs) + a documented preflight + a separate
  integration lane. → step 7.
- **Model-tier mapping is per-runner and heterogeneous** (`claude-*`, `gpt-5.x`, `provider/model`,
  pi any-provider). The codex tier ids were verified in step 7 (models endpoint + pricing docs);
  they will still drift with future model launches — the tier table is the single place to bump.
- **Reimplementation drift** (two separate-language control planes can diverge with no compiler to catch
  it). Mitigated by the single `state.schema.json` tested from both languages + the automated
  cross-language state-equivalence fixture test as a cutover gate. → step 1 + step 11.
- **opencode server lifecycle** (port allocation/collision, readiness-banner drift, crash recovery).
  Real operational complexity hidden behind `start()/stop()`; pin the port + add a health check rather
  than relying solely on stdout scraping. → step 8.
- **HOME-reachable credential files** (`~/.pi/agent/auth.json`, `~/.codex/auth.json`,
  `~/.local/share/opencode/auth.json`) are a residual exfiltration surface the env allowlist alone does
  not close. Decide per runner whether HOME is required / point it at a scrubbed throwaway dir — landed
  as the per-runner allowlist rows `CODEX_HOME` (step 7), `XDG_DATA_HOME` (step 8), and
  `PI_CODING_AGENT_DIR`/`PI_CODING_AGENT_SESSION_DIR` (step 9). → steps 7/8/9 (landed).
- **Single-chokepoint discipline** degrades the instant any adapter hand-builds an env or spreads
  `process.env`. Mitigated by the env-isolation unit test + a lint/grep gate against `...process.env` in
  runner modules.
- **Cross-language additive-field safety.** TS additions (`total_cost_usd`, `session_id`/`thread_id`,
  `runner`, `engine`) must never become load-bearing for Python; Python resume stays functional from v1
  fields + `completed_phases`. → step 11 schema-equivalence test.
- **Squash-merge gating is easy to forget when porting.** It is an explicit parity-checklist line and a
  cutover criterion. → step 5/12.

### Open questions (resolved in the roadmap as **[VERIFY]** steps)

- ~~Exact `canUseTool`/`PermissionResultAllow|Deny` signatures, `permissionMode` values, and
  `max_structured_output_retries` for the Claude Agent SDK?~~ **Resolved in step 6** from the installed
  `sdk.d.ts` 0.3.173 (see the step-6 roadmap entry): signatures as planned, `acceptEdits` exists, and
  there is no retries *option* — only the `error_max_structured_output_retries` result subtype. *(Also
  resolved earlier: env replace-vs-merge = replace; SDK spawns a child;
  `pathToClaudeCodeExecutable`/`executable` need PATH on the allowlist.)*
- ~~Current codex `-codex` model ids for the cheap/mid/capable tiers, and the minimal env for
  ChatGPT-login mode?~~ **Resolved in step 7:** `gpt-5.4-mini`/`gpt-5.4`/`gpt-5.5` (the `-codex`
  suffix is retired); ChatGPT-login needs only `HOME`, API-key mode rides
  `CODEX_API_KEY`/`OPENAI_API_KEY` (see the step-7 roadmap entry).
- ~~Does codex `outputSchema` guarantee JSON-only `finalResponse`, or can prose precede it?~~
  **Resolved in step 7:** documented as JSON but not contractual — the adapter parses defensively
  and the invoker fallback/nudge owns non-conforming replies.
- ~~Does the **v2** opencode prompt route (`@opencode-ai/sdk/v2`) return `.structured` against the pinned
  `^1.17.3`; what is the exact readiness-banner string; are `?directory=`/`x-opencode-directory` honored
  on the v2 prompt route?~~ **Resolved in step 8 (live gate on the real 1.17.3 binary):** `.structured`
  is returned (via a server-injected `StructuredOutput` tool) → `nativeSchema:true` stands; banner =
  `opencode server listening on <url>`; `directory` is an explicit query param on the v2 POSTs and is
  honored. New finding: `--port 0` is not ephemeral (falls back to 4096) → random-port + retry instead
  (see the step-8 roadmap entry).
- ~~Does pi's `--mode json/rpc` give a cleaner stream than `-p`, and how do `AuthStorage`/`agentDir`
  interact with a non-inheriting env?~~ **Resolved in step 9 (installed 0.79.1 + live gate on the real
  binary):** `--mode json` is the cleaner stream — print mode relays every `AgentSessionEvent` as
  JSON-per-line with per-message usage/cost/stopReason and the session header, while `-p` prints final
  text only and `rpc` is a long-lived interactive protocol; `getAgentDir()` reads `PI_CODING_AGENT_DIR`
  (else `$HOME/.pi/agent`) and keys resolve auth.json → allowlisted env vars → models.json, so the
  scrubbed-agentDir mitigation rides the allowlist (see the step-9 roadmap entry).
- Per-runner cost/usage reporting schema and `pricing.ts` coverage for the token-only backends? →
  steps 4/7. *(Codex covered in step 7: the three tiers are priced; codex counts are remapped to the
  disjoint PhaseUsage convention before pricing.)*
- Can transcript/output be streamed from all four runners, or must some be captured post-hoc? → steps
  6–9. *(All four stream; pi streams `text_delta`s live off the `--mode json` line stream, reconciled
  against the authoritative `message_end` text.)*

---

## Changelog vs Python plan

This document replaces the prior **Python `adw_core`** migration plan with a **TypeScript + four-runner**
plan, preserving the original 12-section structure (Goal/scope; D1–D6; target architecture; security
model; runner capability matrix; phase-by-phase mapping; structured output & prompt composition;
state/coexistence; dependency boundary & toolchain; test strategy & parity checklist; incremental
roadmap; risks & open questions). What changed:

- **Reframed as a TypeScript/Node package** (`adw_sdlc/`) with **one `AgentRunner` interface** and four
  interchangeable runners (`claude`, `pi`, `codex`, `opencode`) selected via `--runner`/`MX_AGENT_RUNNER`,
  replacing the single Claude-only stack.
- **Decisions re-derived (same D1–D6 numbering):** D1 = per-backend native SDKs behind one interface
  (drop the Claude-only stack); D2 = LlamaIndex.TS restated language-neutrally (none in the base plan);
  D3 = Node/pnpm/ESM/tsc/tsx/vitest with `optionalDependencies` + dynamic `import()`; D4 = no shared
  package, `state.json` (now versioned with `schema_version`) as the cross-language contract; D5 =
  orchestrator-/SDK-owned OS process boundary + deny-by-default allowlist (not a merging SDK env option);
  D6 = the new `AgentRunner`/`runPhase`/`RunnerCaps` seam.
- **Added** the runner capability matrix (Section 5), the classify-on-Anthropic-SDK-by-default rule,
  per-runner security concretization, Zod schemas replacing Pydantic, native budget gating where
  available, and a 13-step roadmap landing `claude` first.
- **Citations** use real package/symbol names and verified references (`adw/*.py:line`, `@openai/codex-sdk`
  0.139.0, `@opencode-ai/sdk` 1.17.3, `@anthropic-ai/claude-agent-sdk`, `@earendil-works/pi-coding-agent`).

### Changelog vs draft

Review fixes folded into this revision (every blocker/major + the cheap minors), all decisions and
structure preserved:

- **[major] claude fork → `options.env`.** Resolved the env replace-vs-merge [VERIFY] from the shipped
  `sdk.d.ts`: `options.env` **replaces** `process.env` ("Defaults to `process.env`") and `query()`
  already spawns the Claude Code executable as a child (`pathToClaudeCodeExecutable`/`executable`).
  Dropped the bespoke `child/claude-child.ts` from the default path (kept only as a contingency
  `child/spawn-child.ts`); claude now passes the `safeSubprocessEnv()` allowlist directly as `options.env`.
  Updated D5, Sections 1, 4.1, 4.3-1, 4.5, the matrix (`envIsolation:'explicit-no-inherit'`), roadmap
  step 6, and risks.
- **[major] opencode v1 vs v2.** `format:{json_schema}` → `result.structured` exists **only** in
  `@opencode-ai/sdk/v2`; the v1 default export cannot do it. Wired the v2 client explicitly and added a
  step-8 [VERIFY] gate that downgrades opencode to `nativeSchema:false` (fenced-JSON path) if v2 does not
  return `.structured`. Updated D1, D2, Sections 4.3-3, 5, 7, roadmap step 8, risks.
- **[major] pi re-baselined against the shipped SDK.** Confirmed `createAgentSession`, `AuthStorage`/
  `agentDir`, `RpcClient`/`runPrintMode`/`runRpcMode`, and `SessionStats.cost` (native). Set
  `caps.costUsd:true`, dropped the "dark / CLI-only / cost via a different registry" framing, kept
  `nativeSchema:false` (no `responseFormat` in `PromptOptions`), and documented that
  `AgentSession.prompt()` returns `void` and emits via the `subscribe()` event bus (output captured via
  listeners, not a return value). Pinned `0.79.1` (npm-resolved). Updated D1, Sections 4.3-4, 5, 7,
  roadmap step 9, risks.
- **[minor] native budget gating + scoped price table.** Use claude's native `maxBudgetUsd` /
  `error_max_budget_usd` / `total_cost_usd`; scope the parent `pricing.ts` table to **token-only**
  backends (codex, anthropic classify). Added `nativeBudget` to `RunnerCaps` and a `signal:'budget'`
  fast-fail. Updated D1, Sections 3.2, 6, 7, 10, risks.
- **[minor] CLAUDE_BIN / executable-on-PATH closed.** Set `pathToClaudeCodeExecutable` from the resolved
  binary and keep `PATH`/`HOME` on the allowlist so the SDK can locate/spawn its runtime; removed from
  the open [VERIFY] list. Updated Sections 1, 4.3-1, roadmap step 6.
- **[minor] codex `apiKey`→`CODEX_API_KEY` guard.** Kept the (correct) claim and added that the
  secret-withholding test must assert on the **SDK-built spawned child env**, not just the allowlist
  object, so an `apiKey`-routed key cannot slip past. Updated Sections 4.3-2, 8 (criterion 4), 10.
- **[minor] codex env tightened to always-pass.** Made the codex adapter pass `safeSubprocessEnv()`
  **unconditionally** (omission flips codex to full-inherit, `dist/index.js:234-239`) and added a unit
  test + lint/grep gate asserting codex is never constructed without `env`. Updated D3, Sections 4.4,
  9, 10, roadmap step 7, risks.
