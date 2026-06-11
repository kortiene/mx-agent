# adw_sdlc Memory Stack — Decision Record

**Scope:** the technology stack for the deferred **cross-run institutional-memory** feature
(plan decision **D2**) — indexing a small, off-tree, append-only corpus (gitignored
`agents/{adw_id}/` transcripts + `state.json` `review_findings` with severity/`file:line` +
closed-issue/merged-PR threads via `gh`) and injecting "prior art" into the `plan`/`implement`/`review`
prompts. Runner-agnostic; built and queried by the TypeScript control plane (never by a runner), so the
secret boundary is preserved (the agent receives retrieved **text**, never `GH_TOKEN`).

**Status:** Decided. Feature remains **deferred / optional / post-cutover** per D2 — this record fixes
*what to build it with* when it lands, so the choice is not re-litigated.

---

## TL;DR

- **Skip LlamaIndex** (and every peer framework). For this corpus on a secrets-owning control-plane CLI,
  a RAG/agent framework is the wrong category — and LlamaIndex.TS specifically is **end-of-life**.
- **Use `better-sqlite3` + FTS5/BM25** for lexical retrieval. One native dep; the `.db` file *is* the
  persistence; `SQL WHERE` gives metadata filters (severity, `file:line`, issue#, run-id). Start here.
- **Defer semantic embeddings.** The corpus is exact-match-heavy text where BM25 is the *right* tool, and
  embeddings are not free (`transformers.js` ≈ 720 MB `onnxruntime-node` tree on a sensitive process).
- **Growth path = `sqlite-vec`**, loaded *into the same `better-sqlite3` handle* (vectors beside the FTS5
  table → hybrid BM25+cosine, same dep family, no migration). Add only on a concrete recall trigger; prefer
  a **hosted embeddings API** over an embedded model at that point.

---

## Part 1 — LlamaIndex: skip (verdict from the dedicated evaluation)

The original thread of this work — *"how could we leverage LlamaIndex to improve ADW?"* — resolves to
**no**, for two independent reasons:

1. **It's end-of-life in TypeScript.** Verified live on npm (2026-06-10):
   - `@llamaindex/core@0.6.23`, `@llamaindex/workflow@1.1.25`, `@llamaindex/anthropic@0.3.27` →
     *"This package is deprecated and no longer maintained."*
   - `llamaindex@0.12.1` is stale (last publish 2025-12-02) and depends on those deprecated packages; repos
     archived; vendor steers TS users to Python LlamaAgents.
   - Adopting an archived framework as a load-bearing dependency on a secrets-owning control plane is
     disqualifying on its own.

2. **It loses on the merits even ignoring deprecation.** Every candidate use maps to a leaner native/stdlib
   approach already chosen:

   | LlamaIndex use | Verdict | Leaner winner |
   |---|---|---|
   | Cross-run memory / RAG | skip | `better-sqlite3` FTS5/BM25 (+ optional embeddings) |
   | Structured / Zod per-phase output | skip | runners' native schema output + Anthropic SDK `messages.parse` |
   | Workflow / agent orchestration | skip (firmest) | deterministic TS loops — ceding the loop is a security regression |
   | LLM-as-judge eval | idea: maybe-later; LlamaIndex: skip | a ~20-line in-house `structuredCall<T>()` judge |
   | Semantic conditional gating | skip | the classify change-type already produced + a direct Zod yes/no |
   | Observability / tracing | skip | existing `agents/{adw_id}/` transcripts + per-runner native cost/usage |

   For the *one* plausibly-yes use (memory), LlamaIndex.TS never shipped the two things that would justify a
   framework: **no hybrid/QueryFusion retriever** (Python-only) and **no local/embedded vector store** (all
   TS stores are network DBs). Its embedded store is a brute-force in-memory JSON cosine; its BM25 wraps
   in-memory `okapibm25` — both weaker than `better-sqlite3` FTS5.

---

## Part 2 — Alternatives evaluated

"Alternatives to LlamaIndex" split into two groups. Neither changes the verdict. All statuses verified live
on npm (2026-06-11).

### Tier 1 — Peer frameworks (same category as LlamaIndex): wrong category

| Framework | npm status | Why not here |
|---|---|---|
| **LangChain.js** | `@langchain/core@1.1.48` ok; **`@langchain/community@1.1.29` deprecated** | Heavy; re-does orchestration/structured-output D1/D3 do natively; community tier already rotting (LlamaIndex.TS trajectory) |
| **Mastra** | `@mastra/core@1.41.0` ok but **28 direct deps** (ships `ws`, `posthog-node`) | Full agent framework + telemetry surface for a 2.3 MB corpus on a secrets-owning CLI |
| **Vercel AI SDK** | `ai@6.0.201` ok, lean (4 deps) | Not a RAG/memory tool — an LLM-call/agent toolkit; solves an already-solved problem |
| **Genkit** | alive | Google/Firebase-oriented framework; wrong category + heavier |
| **EmbedJS** (closest LlamaIndex analog) | **stale** (last publish 2025-11-14), depends on `langchain-core` | Same rot trajectory; disqualifying for a control-plane dep |

Most peers are *alive* (unlike LlamaIndex.TS), but all are the same **category mistake**.

### Tier 2 — Composable primitives (what the recommendation is built from)

| Option | npm status | Verdict |
|---|---|---|
| **better-sqlite3** (FTS5/BM25) | `12.10.0` (2 deps) | ✅ **Use now** — `.db` is persistence; SQL `WHERE` metadata filters |
| **sqlite-vec** | `0.1.9` (0 deps, **pre-1.0**) | 🔶 **Growth path** — loads into the same handle; hybrid BM25+cosine, no migration |
| **@orama/orama** (pure-JS hybrid) | `3.1.18` (0 runtime deps), **~6 mo stale** (pub 2025-12-19) | ❌ Closest pure-JS peer, but staleness mirrors LlamaIndex.TS + manual persistence (no `.db` store, no SQL filters) |
| **@lancedb/lancedb** (embedded vector DB) | `0.30.0` ok | ❌ Reserve only for a non-credible 100k-vector / latency-SLA future |
| **fastembed-js / faiss-node** | archived / abandoned (faiss-node repo last pushed 2023) | ❌ Dead — disqualifying |

> Note: `@orama/orama` core has **0 runtime deps** (no bundled telemetry — telemetry is a separate opt-in
> plugin); the rejection rests on staleness + manual persistence, not telemetry.

---

## Part 3 — Recommended stack (= plan D2, unchanged)

**Now — lexical only:**

- `better-sqlite3` with an **FTS5 virtual table** for BM25 ranking, and `SQL WHERE` for metadata filters
  (severity, `file:line`, issue#, run-id).
- The gitignored, off-tree `.db` file *is* the persistence layer; append = `INSERT`. No second store, no
  server, no network. One native dep on the control plane.
- **Do not add semantic embeddings yet.** The corpus is exact-match-heavy (error strings, `file:line`,
  issue/PR numbers, severity tags) where BM25 is correct, not a compromise; and embeddings cost a ~720 MB
  `onnxruntime-node` tree + model download on the `GH_TOKEN`/Matrix-owning process.

**Growth path — add only on a recall trigger:**

- Add **`sqlite-vec`** as a loadable extension into the *existing* `better-sqlite3` handle (it supports
  `loadExtension`). Vectors live in the **same `.db`** beside the FTS5 table → true hybrid BM25+cosine.
  Additive and removable; no data migration, no second process, same dep family.
- **Embedder at that point:** prefer a **hosted embeddings API** (the control plane is already authenticated
  for per-phase LLM calls → zero new trust boundary, zero native/ONNX dep) over an embedded model. Use an
  embedded embedder (`@huggingface/transformers` / `@mastra/fastembed`) **only** under a hard air-gap/offline
  requirement.
- **Reserve `@lancedb/lancedb`** only for a non-credible 100×+ / 100k-vector future with latency SLAs.

**Concrete trigger for the growth path:** manual spot-checks of prior-art injection show it missing findings
a human would call obviously related — i.e. paraphrase/synonym recall starts mattering (a finding phrased
*"race in the approval path"* must retrieve a prior *"concurrency bug in `expires_at` handling"*), **or** the
corpus crosses ~hundreds of runs / multi-source chunking where cross-vocabulary matches slip past BM25.

---

## Part 4 — Caveats (do not hand-wave these)

1. **`sqlite-vec` ↔ `better-sqlite3` SQLite-ABI coupling.** `sqlite-vec` ships a prebuilt extension compiled
   against a specific SQLite version, while `better-sqlite3` statically bundles its **own** SQLite. There are
   documented cases where the extension *loads but registers zero functions* due to an ABI mismatch (and
   reports of load failures on Windows). So the "same dep" future is real but requires: pinning `sqlite-vec`'s
   binary to a SQLite version ABI-compatible with the `better-sqlite3` release in use, **plus a startup check
   that the `vec0` functions actually registered** (not merely that `loadExtension()` did not throw).
2. **Semantic embeddings are not free.** `transformers.js` pulls ~720 MB of `onnxruntime-node`. This is the
   main reason to (a) stay lexical-first and (b) prefer a hosted embeddings API if/when semantic is needed.
3. **`sqlite-vec` is pre-1.0** (brute-force KNN). Acceptable because brute-force over a few thousand vectors is
   sub-millisecond and the dependency is additive/removable — but track its 1.0.

---

## Verification log

- **LlamaIndex.TS deprecation** — verified against the live npm registry 2026-06-10: `@llamaindex/core`,
  `@llamaindex/workflow`, `@llamaindex/anthropic` all carry the deprecation flag; `llamaindex` stale + depends
  on them.
- **Alternatives maintenance** — verified against the live npm registry 2026-06-11 (latest version, publish
  date, deprecation flag, direct-dep count): `better-sqlite3@12.10.0` ok; `sqlite-vec@0.1.9` ok; 
  `@lancedb/lancedb@0.30.0` ok; `@langchain/core@1.1.48` ok / `@langchain/community@1.1.29` deprecated;
  `@mastra/core@1.41.0` ok (28 deps); `ai@6.0.201` ok; `@orama/orama@3.1.18` ok-but-stale (pub 2025-12-19).
- **Re-confirm at adoption time** — package maintenance status drifts; re-run these checks before installing,
  and pin the `sqlite-vec`/`better-sqlite3` ABI pair.

---

## Relationship to `PLAN.md`

This record **does not change** decision **D2** ("no LlamaIndex in the base migration; cross-run memory
deferred, optional, post-cutover, not pre-committed to a framework"). It supplies the decided implementation
stack for that deferred feature: `better-sqlite3` FTS5 now → `sqlite-vec` in the same file later → hosted
embeddings if semantic recall is ever required.
