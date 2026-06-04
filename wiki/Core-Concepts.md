# Core Concepts

This page explains mx-agent's primitives and its state model — the *why* behind the design, not just the *how*. Read [[Getting Started|Getting-Started]] first if you haven't run the tool yet.

---

## Primitive Glossary

| Primitive | Definition | Matrix mapping | Identity / key |
|---|---|---|---|
| **Workspace** | A shared coordination context for one project. All discovery, context sharing, tasks, and execution happen inside it. | A Matrix **room** | Room ID `!…:server` (alias `#…:server`) |
| **Agent** | A daemon persona representing one coding agent or runtime (Claude Code, Pi, a build box). Advertises capabilities and tools; can request and/or serve execution. | `com.mxagent.agent.v1` **state event** | `state_key = <agent_id>`; bound to a Matrix user/device and an Ed25519 signing key |
| **Task** | A durable node in the work graph: a unit of intended work with state, dependencies, and an assignee. Survives restarts. | `com.mxagent.task.v1` **state event** | `state_key = <task_id>` |
| **Invocation** | One concrete *run* of a command or tool call — created, executing, then terminal. The bridge between "we intend to run X" (task) and "X is producing output now" (streams). | `com.mxagent.invocation.v1` **state** + `exec`/`call` **timeline events** | `invocation_id` (e.g. `inv_01HZ…`) |
| **Stream** | The live byte channels of one invocation: `stdin`, `stdout`, `stderr`, `pty`, `control`. Ordered, chunked, resumable, and **decoupled** from durable state. | `com.mxagent.stream.chunk.v1` timeline events / media artifacts | keyed by `(invocation_id, stream, seq)` |

A useful way to hold these together: **a Task says what should happen, an Invocation is one attempt at making it happen, and Streams are what that attempt is saying out loud.** An Agent owns both ends — requesting and serving — and a Workspace is the room they all live in.

---

## The Timeline Graph vs. State Flags

A naive orchestrator stores a mutable row:

```jsonc
// The anti-pattern mx-agent rejects:
{ "task": "run-tests", "status": "running", "worker": "pi", "updated_at": "…" }
```

This breaks the moment you have more than one machine:

- **Lost updates.** Two daemons write `status` near-simultaneously; last-write-wins silently erases one. You can't tell *who* set it or *why*.
- **No history.** "It says `failed` now" — but failed when, after which attempt, observed by whom? The flag is amnesiac.
- **No durable recovery.** A daemon that was offline can't reconstruct what it missed; the flag only shows the present.
- **A central writer.** Someone has to own the mutable row — reintroducing the central server mx-agent exists to avoid.

mx-agent instead treats coordination as an **event-sourced, append-only log over Matrix**, with two complementary surfaces:

1. **Timeline events** = the immutable activity stream. Every `exec.request`, `stream.chunk`, `exec.finished`, `approval.decision` is appended, never edited. This is the audit trail and the DAG's edges-in-motion.
2. **State events** = the durable, queryable snapshot. `com.mxagent.task.v1` / `agent.v1` / `invocation.v1` give you "the current truth" without replaying the whole log.

**Why append-only wins here:**

- **Federation-native.** Matrix already replicates room history with ordering and durability across homeservers. mx-agent gets distributed, restart-surviving state *for free* by piggybacking on it — no bespoke consensus.
- **Provenance.** Every change is an event with a sender, a timestamp, and (for privileged events) an Ed25519 signature. "Who asked for this and could they?" is always answerable. A status flag can't be signed; an event can.
- **Reconstructable.** A daemon that restarts resumes `/sync` from its stored token, replays missed events, and rebuilds invocation state and stream cursors. (See architecture §11.3.)
- **The DAG is explicit.** Tasks carry `depends_on` / `blocks` arrays, forming a Directed Acyclic Graph:

```text
task-plan  succeeded
  └─ task-code  succeeded
      └─ task-test  failed
          └─ task-review  blocked
```

A task is **runnable** only when *all* of these hold (architecture §9.2):

```text
state ∈ {pending, assigned}
∧ every depends_on task is succeeded
∧ the assigned agent is active
∧ local policy permits the operation
∧ no conflicting newer state_rev exists
```

Task lifecycle:

```text
proposed → pending → assigned → executing → succeeded
                                   ├──────→ failed
                                   └──────→ cancelled
         → blocked
         → superseded
```

### State *does* still exist — but it's versioned, not authoritative-by-fiat

State events aren't free of concurrency; mx-agent just makes the conflict *visible and resolvable* instead of silent:

- Each mutable state event carries a monotonic **`state_rev`** and a **`previous_event_id`**.
- Clients treat a **lower or repeated `state_rev` as stale** and ignore it.
- Matrix **power levels** plus local mx-agent **policy** restrict *who* may mutate `task`/`exec`/`call`/`trust` events at all.
- For genuinely contentious workflows, agents append **timeline decision events** and let a designated coordinator agent fold them into resolved state — turning a race into an explicit, auditable negotiation.

---

## Concurrency, Forks, and Conflict Resolution

mx-agent is built for *many* agents acting at once. Here is exactly how parallelism is kept sane.

### Parallel invocations

Each run gets a unique `invocation_id`. Streams are ordered **per invocation**, by the triple `(invocation_id, stream, seq)` — so ten commands streaming at once never interleave or corrupt each other's output. An agent advertises a concurrency ceiling in its state:

```json
"load": { "running_invocations": 1, "max_invocations": 4 }
```

The daemon refuses or queues work beyond `max_invocations`, giving natural per-agent backpressure.

### Forks in the task timeline

Because tasks form a DAG (not a line), the graph naturally **fans out and back in**:

```text
                 ┌─ task-test-api    (developer-pi)   ┐
task-code ───────┤                                    ├──→ task-review
                 └─ task-test-web    (runner-ci)      ┘
```

`task-code` *blocks* both test tasks; `task-review` *depends_on* both. The two test tasks are independent, run on different agents in parallel, and `task-review` only becomes runnable once **both** reach `succeeded`. This is a fork-join expressed purely through `depends_on` / `blocks` — no scheduler process required.

### Conflict resolution

Matrix room state is **last-write-wins per `(type, state_key)`**. mx-agent layers four defenses on top so "last write" is rarely a surprise (architecture §9.4):

1. **Optimistic concurrency** — `state_rev` + `previous_event_id`; stale writes are detected and dropped by readers. (`task update` accepts `--expected-state-rev` to fail loudly on a race rather than clobber.)
2. **Authorization** — power levels + policy mean only entitled agents can write a given state at all, shrinking the set of possible writers.
3. **Idempotency** — privileged requests carry `request_id`, `idempotency_key`, `nonce`, and `expires_at`; replays and duplicates are de-duplicated, expired requests are ignored (architecture §11.2).
4. **Coordinator pattern** — for high-contention work, agents *propose* via timeline events and one coordinator agent *commits* the resolved state, serializing the decision without a central server.

The throughline: **mx-agent never hides a conflict behind a mutable flag. It signs every claim, versions every snapshot, and makes disagreement an explicit, auditable event.**

---

## See also

- Wire formats for every event above: [[Stream & Protocol Spec|Stream-and-Protocol-Spec]]
- How trust and policy gate these operations: [[Security & Sandboxing|Security-and-Sandboxing]]
- A worked multi-agent example: [[AI Agent Orchestration|AI-Agent-Orchestration]]
