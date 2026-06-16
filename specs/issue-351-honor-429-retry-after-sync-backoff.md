# Honor HTTP 429 `Retry-After` for server-directed sync backoff

> Spec for GitHub issue #351 (`type:feature`, `area:matrix`, `priority:p2`).
> Planning document only — no implementation is performed here.

## Problem Statement

The daemon's long-lived Matrix `/sync` loop
(`crates/mx-agent-daemon/src/sync.rs`) recovers from any non-auth error with a
**blind exponential backoff** (`BackoffConfig { base: 1s, max: 60s, factor: 2 }`).
Every error that is not an unknown/missing token is classified as
`StepError::Transient` and retried on that fixed schedule. The loop does **not**
look at HTTP `429 Too Many Requests` / `M_LIMIT_EXCEEDED` responses, so it never
sizes its wait to the homeserver's `Retry-After` (the `retry_after_ms` body field
or the `Retry-After` header). The daemon also never sets an explicit matrix-sdk
`RequestConfig` retry policy — both `build_client` and `build_client_with_store`
in `crates/mx-agent-daemon/src/matrix.rs` call `Client::builder()…build()` with
SDK defaults.

`docs/architecture.md` §11.4 claims that on a homeserver rate limit the *daemon*
"backs off, chunks less frequently, may switch to artifact mode." Only one of
those is real and none of it is driven by a 429: the daemon's sync backoff is
blind, the stream emitter's `max_events_per_second` token bucket
(`crates/mx-agent-daemon/src/stream.rs`) is a **static, per-invocation** cap, and
artifact mode triggers on **output size**, not on observed rate-limit responses.
§8.4 likewise lists "events_per_second exceeds homeserver rate limits" as an
artifact-mode trigger that is not wired. This is the A2 (docs-accurate: partial)
gap noted in the 2026-06-14 re-assessment and the #274 closing comment.

This issue asks to (a) make the daemon's rate-limit backoff respect the
server-directed `Retry-After`, and (b) reconcile the architecture doc with what is
actually implemented.

## Goals

- The daemon's `/sync` loop sizes its post-rate-limit wait from the homeserver's
  `Retry-After` when one is provided, instead of always using the blind
  exponential schedule.
- The honored delay is **clamped to a sane ceiling** so a hostile or
  misconfigured homeserver cannot wedge the sync loop with an enormous
  `Retry-After`, and remains **interruptible** so `daemon stop` still wakes
  promptly.
- The daemon sets an **explicit, documented** matrix-sdk `RequestConfig` retry
  policy on the client builder so the SDK's internal retry-with-`Retry-After`
  behavior is intentional and bounded, not an accident of defaults.
- `daemon status` can distinguish a rate-limited backoff from a generic transient
  failure (so operators see *why* sync is paused), without leaking secrets.
- `docs/architecture.md` §11.4 (and §8.3/§8.4 where they over-claim) describe the
  behavior that actually ships — no implied "chunk less frequently / switch to
  artifact mode on 429" that does not exist.

## Non-Goals

- **Dynamically throttling the stream emitter or switching to artifact mode in
  response to a sync 429.** The stream token bucket and artifact-offload decision
  live on a different code path (`stream.rs` / exec output handling) and do not
  observe `/sync` responses. Wiring a live 429 signal into stream throttling is a
  larger, separate change; this spec only *reconciles the docs* to stop claiming
  it and leaves it as explicit future work.
- Changing the chunking defaults, output caps, or artifact thresholds.
- Honoring `Retry-After` on every Matrix request the daemon makes (exec sends,
  task state writes, media upload). The SDK's per-request retry already covers
  those; this spec is scoped to the **sync loop's own** backoff plus a
  deliberate client-wide `RequestConfig`.
- Any Windows or non-Unix consideration (the project is Unix-only).

## Relevant Repository Context

### Owning crate and modules

- **`mx-agent-daemon`** owns all long-lived Matrix state and the sync loop. The
  CLI is stateless and never holds tokens or device keys — that boundary is
  unchanged by this work.
- `crates/mx-agent-daemon/src/sync.rs` — the generic `run_sync_loop` (generic over
  a `step` future), the `Backoff`/`BackoffConfig` state machine, `StepError`
  (`Transient`/`Fatal`), `SyncState`/`SyncHealth`, `is_fatal_sync_error`, and
  `run_matrix_sync[_with_subscribers]` which wires the loop to a real
  `matrix_sdk::Client::sync_once`. This is the primary edit site.
- `crates/mx-agent-daemon/src/lifecycle.rs` (`spawn_matrix_workers`, ~L412)
  constructs the live loop with `BackoffConfig::default()`.
- `crates/mx-agent-daemon/src/matrix.rs` (`build_client` ~L174,
  `build_client_with_store` ~L196) — the two `Client::builder()` sites where a
  `RequestConfig` would be set.
- `crates/mx-agent-daemon/src/watch.rs` — the `task watch` loop has its **own**
  `BackoffConfig`/`Backoff` reuse (`WatchConfig`, `run_watch`) and its own
  transient/fatal classification via `is_fatal_sync_error`. It shares the same
  blind-backoff gap; honoring `Retry-After` there too is a small, consistent
  follow-on (see Open Questions).

### How matrix-sdk 0.18 already handles 429 (critical — read before implementing)

The implementer must understand that **matrix-sdk 0.18 already honors
`Retry-After` internally** for rate-limited requests, so the daemon-level work is
about *observability, bounding, and the residual gaps*, not about re-implementing
retry from scratch.

In the vendored SDK (`matrix-sdk-0.18.0/src/http_client/native.rs` and
`src/error.rs`):

- The native HTTP client retries transient failures with `backon`'s exponential
  backoff (min 500 ms, max 60 s, **total budget 15 min**, *no* max-times) unless
  the request's `RequestConfig` overrides `retry_limit` / `max_retry_time`.
- A `429`/`M_LIMIT_EXCEEDED` maps to `RetryKind::Transient { retry_after }`:
  - `ErrorKind::LimitExceeded(LimitExceededErrorData { retry_after: Option<RetryAfter> })`
    with `RetryAfter::Delay(Duration)` (the `retry_after_ms` body field, or a
    *numeric* `Retry-After` header) **is honored** — the SDK waits that long.
  - `RetryAfter::DateTime(SystemTime)` (an HTTP-date `Retry-After` header) is
    **discarded** (`from_retry_after` maps `DateTime` → `None`) and the SDK falls
    back to the exponential schedule.
  - A bare `429` with no `errcode`/`retry_after` → `Transient { retry_after: None }`
    → exponential.

**Consequences for this issue:**

1. With the current defaults, a sync 429 is mostly *absorbed inside*
   `client.sync_once(...)`: the SDK blocks (honoring `retry_after_ms`) and only
   surfaces a `LimitExceeded` error to `run_sync_loop` after the 15-minute budget
   is exhausted — at which point the loop applies its *own* blind exponential on
   top (double backoff), and `daemon status` shows a long, unexplained
   `Degraded`/stall with no rate-limit signal.
2. The SDK's internal sleep is **not interruptible** by the loop's `running`
   flag, so a long `retry_after_ms` can block `sync_once` (and delay clean
   shutdown / freeze the health snapshot) for minutes.
3. The HTTP-date `Retry-After` header form is silently ignored by the SDK.

So the coherent design is: **set an explicit, bounded `RequestConfig` for sync**
so a sustained rate-limit surfaces to the loop *promptly*, and have the **loop**
own the visible, interruptible, `Retry-After`-honoring backoff (covering the
DateTime-header form and post-budget behavior the SDK does not).

### Error-extraction API (already used in this file)

`sync.rs` already calls `error.client_api_error_kind() -> Option<&ErrorKind>`
(see `is_fatal_sync_error`). The new classifier matches
`ErrorKind::LimitExceeded(data)` and reads `data.retry_after`. Types live at
`matrix_sdk::ruma::api::error::{ErrorKind, LimitExceededErrorData, RetryAfter}`
(the file already imports `ErrorKind` from that path).

### Conventions to preserve

- No `unsafe`; MSRV is now **1.93** (README/CONTRIBUTING; the issue text's "1.74"
  is stale — do not lower it). Use only ≤1.93 APIs.
- `missing_docs` is denied in CI — document every new public item (new
  `StepError` variant, new `BackoffConfig` field, new `SyncHealth` field/state,
  new helper).
- Human-readable status by default, `--json` for automation — any new status
  field must render in both.
- No secrets in logs; reuse the existing non-sensitive `tracing` style (the loop
  already logs only error strings/metadata). A homeserver error string is
  non-sensitive but keep messages terse and factual.
- Keep `run_sync_loop` generic and testable without a live homeserver: the 429
  classification must live in the `run_matrix_sync` step closure (which has the
  `matrix_sdk::Error`), and the generic loop must only see a typed
  `StepError`/delay — so the new behavior stays unit-testable with injected steps.

## Proposed Implementation

Two cooperating layers; both are in scope.

### Layer 1 — sync-loop honors `Retry-After` (primary)

1. **New step outcome.** Add a variant to `StepError`:

   ```rust
   /// A homeserver rate-limit (HTTP 429 / `M_LIMIT_EXCEEDED`). `retry_after` is
   /// the server-directed wait when one was supplied; `None` falls back to the
   /// exponential backoff schedule.
   RateLimited { retry_after: Option<Duration> },
   ```

   (Additive: the only exhaustive matcher is `run_sync_loop`; constructors of
   `Transient`/`Fatal` are unaffected.)

2. **Classifier.** Add a pure, unit-testable helper that maps the rate-limit
   error kind to a clamped `Option<Duration>` *relative to a passed-in `now`* so
   `DateTime` can be tested deterministically:

   ```rust
   /// Extract a server-directed retry delay from a rate-limit error kind,
   /// clamped to `[Duration::ZERO, ceiling]`. Returns `None` when the kind is not
   /// a rate limit or carries no usable delay (caller falls back to backoff).
   pub(crate) fn rate_limit_retry_after(
       kind: &ErrorKind,
       now: SystemTime,
       ceiling: Duration,
   ) -> Option<Duration>
   ```

   - `RetryAfter::Delay(d)` → `Some(d.min(ceiling))`.
   - `RetryAfter::DateTime(t)` → `Some(t.duration_since(now).unwrap_or(ZERO).min(ceiling))`
     (a past instant collapses to `ZERO`).
   - Anything else / `retry_after == None` → `None`.

   Add a sibling predicate `is_rate_limit_error(&matrix_sdk::Error) -> bool`
   (matches `ErrorKind::LimitExceeded(_)`, and optionally a bare HTTP 429 if the
   SDK exposes the status — otherwise just `LimitExceeded`) so the step closure
   can branch cleanly alongside `is_fatal_sync_error`.

3. **Wire into the step.** In `run_matrix_sync_with_subscribers`'s `Err(e)`
   branch, classify in order: fatal → rate-limited → transient:

   ```rust
   Err(e) => {
       if is_fatal_sync_error(&e) {
           Err(StepError::Fatal(e.to_string()))
       } else if is_rate_limit_error(&e) {
           let retry_after = e.client_api_error_kind()
               .and_then(|k| rate_limit_retry_after(k, SystemTime::now(), cfg.rate_limit_ceiling));
           Err(StepError::RateLimited { retry_after })
       } else {
           Err(StepError::Transient(e.to_string()))
       }
   }
   ```

   (`cfg.rate_limit_ceiling` per the new config field below; or pass the ceiling
   in. Keep `now`/ceiling as parameters so the helper stays deterministic.)

4. **Handle in the generic loop.** Add a `StepError::RateLimited { retry_after }`
   arm to `run_sync_loop`:
   - Compute `delay = retry_after.unwrap_or_else(|| backoff.next_delay())`. When
     `retry_after` is `Some`, still advance/escalate the exponential
     (`let floor = backoff.next_delay(); delay.max(floor)`) so *repeated* rate
     limits ratchet up rather than hammering at exactly the server minimum, but
     the loop never waits **less** than the server asked.
   - Record a rate-limited health state (see Layer 1.5), then
     `sleep_interruptible(delay, &running).await` — reuse the existing
     50 ms-chunked interruptible sleep so `daemon stop` still wakes within ~50 ms
     even for a multi-minute clamp.
   - On the next success, `backoff.reset()` already runs (existing code), so a
     transient blip after recovery is cheap again.

5. **Health surface (Layer 1.5).** Make `daemon status` show *why* sync is
   paused. Two options — pick per Open Questions:
   - *Recommended (minimal, non-breaking):* keep state `Degraded` and add an
     additive, `skip_serializing_if = "Option::is_none"` field
     `rate_limited_secs: Option<u64>` (the honored delay) plus a clear
     `last_error` like `"rate limited by homeserver; retrying in {n}s"`. A new
     `SyncHealth::record_rate_limited(delay, now)` setter records it; success
     clears it.
   - *Alternative:* add a `SyncState::RateLimited` enum variant. More expressive
     but widens the serialized status enum; only the daemon renders it, so it is
     controllable, but it is a (small) status-surface change.

### Layer 2 — explicit, bounded `RequestConfig` (deliberate SDK retry)

In `matrix.rs`, set a documented retry policy on **both** builders so the SDK's
internal retry is intentional and *bounded*, letting Layer 1 own the long,
observable backoff:

```rust
use matrix_sdk::config::RequestConfig;
// Bound the SDK's internal retry so a sustained rate-limit surfaces to the
// daemon sync loop promptly (which honors Retry-After visibly + interruptibly,
// issue #351) instead of blocking inside one sync_once for the SDK's 15-minute
// default budget.
let request_config = RequestConfig::default().max_retry_time(Duration::from_secs(/* e.g. 30 */));
Client::builder().homeserver_url(url).request_config(request_config)/* … */.build()
```

- Recommended: a bounded `max_retry_time` (≈30 s) — the SDK still smooths
  momentary 429s within the bound; anything longer becomes the loop's job. (Do
  **not** use the SDK's no-limit default, and avoid `disable_retry()` unless we
  decide the loop should own *all* retry — see Open Questions.)
- Apply identically in `build_client` and `build_client_with_store` so loopback
  and store-backed daemon clients behave the same. (`build_client` is the
  unauthenticated builder; setting the config there is harmless and keeps the two
  in lockstep.)

### `BackoffConfig` addition

Add a `rate_limit_ceiling: Duration` field (clamp for honored `Retry-After`),
default ~5 minutes, with `#[derive(...)]` and a doc comment. Update the existing
`Default` impl and the `fast_backoff()` test helper. Keep `base`/`max`/`factor`
semantics for the non-rate-limit transient path unchanged.

## Affected Files / Crates / Modules

| File | Change |
|---|---|
| `crates/mx-agent-daemon/src/sync.rs` | New `StepError::RateLimited`; `rate_limit_retry_after` + `is_rate_limit_error` helpers; `run_sync_loop` arm; `BackoffConfig.rate_limit_ceiling`; `SyncHealth::record_rate_limited` (+ field or `SyncState::RateLimited`); wire classification into the `run_matrix_sync` step; unit tests |
| `crates/mx-agent-daemon/src/matrix.rs` | Set explicit `RequestConfig` (bounded `max_retry_time`) on `build_client` and `build_client_with_store`; doc the rationale; possibly a small unit test asserting the builder is configured |
| `crates/mx-agent-daemon/src/lib.rs` | Re-export any newly public item if the `RateLimited` variant / new health field needs it (the module already re-exports `StepError`, `SyncHealth`, `SyncState`, `BackoffConfig`) |
| `crates/mx-agent-daemon/src/lifecycle.rs` | No behavior change required (uses `BackoffConfig::default()`); confirm the default ceiling is sensible for production |
| `crates/mx-agent-daemon/src/watch.rs` | *Optional, recommended for consistency:* honor `RateLimited` in `run_watch`'s backoff too (it shares `BackoffConfig`/`is_fatal_sync_error`) |
| Status rendering (daemon `status` IPC handler / CLI formatter) | If a new health field/state is added, render it in human and `--json` output |
| `docs/architecture.md` | Reconcile §11.4, §8.3, §8.4 (see Documentation Updates) |
| `README.md` | Status-table touch only if behavior visibly changes (see Documentation Updates) |

To read first: `sync.rs` (whole), `matrix.rs` L160–215, `lifecycle.rs` L330–430,
`watch.rs` L35–130, `docs/architecture.md` §8 and §11.

## CLI / API Changes

- **CLI surface:** none required. No new flags or commands. If Layer 1.5 adds a
  health field/state, `daemon status` (human) and `daemon status --json` gain one
  read-only field (e.g. `rate_limited_secs` or a `rate_limited` state) — additive,
  no flag changes, preserves human-default/`--json` parity.
- **Public Rust API (within `mx-agent-daemon`):** additive — new `StepError`
  variant, new `BackoffConfig` field, new `SyncHealth` method/field, new helper
  fns. All must carry doc comments (`missing_docs` is denied). No breaking
  signature changes to `run_sync_loop`/`run_matrix_sync`.
- **IPC/protocol:** no JSON-RPC method changes; the only wire delta is the
  additive status field above.

## Data Model / Protocol Changes

- No Matrix event schema, policy, persistence, or signing changes. `Retry-After`
  handling is purely transport/runtime behavior.
- `SyncHealth` serialization gains at most one additive, optional field (or one
  new `SyncState` enum value). It is a non-sensitive status snapshot (already
  contains no tokens) and is forward-compatible: old consumers ignore an unknown
  field; the new state value is only produced and consumed by the daemon.
- The persisted **sync token** format and semantics are unchanged.

## Security Considerations

- **DoS clamp (must-have):** honored `Retry-After` is clamped to
  `rate_limit_ceiling` so a compromised/misconfigured homeserver cannot pin the
  sync loop offline for an unbounded time with a giant `retry_after_ms` or a
  far-future HTTP-date. A past/zero/negative value collapses to `Duration::ZERO`.
- **Shutdown responsiveness:** the wait must go through `sleep_interruptible`
  (50 ms chunks honoring `running`), not a single `tokio::time::sleep`, so a
  rate-limit backoff never blocks `daemon stop`. Bounding the SDK's
  `max_retry_time` (Layer 2) closes the complementary gap where the SDK's own
  *internal* sleep (inside `sync_once`) is not interruptible.
- **No secret exposure:** the loop already logs only error strings and
  non-sensitive metadata; the rate-limit path adds only a duration and a fixed
  message. No tokens, device keys, room content, or `Retry-After`-derived
  identifiers are logged. The `SyncHealth` snapshot stays token-free.
- **Boundaries unchanged:** the CLI still never sees Matrix tokens/device keys;
  room membership still confers no execution rights; Ed25519 signing + trust +
  deny-by-default policy + approval remain the execution gate. This change touches
  only sync transport backoff and does not relax any authorization check.
- **Unix-only:** no platform assumptions added; `Duration`/`SystemTime` math is
  portable and the code stays `#![forbid(unsafe_code)]`-clean.

## Testing Plan

Unit tests (no homeserver needed — the design keeps classification pure and the
loop injectable):

- `rate_limit_retry_after`:
  - `RetryAfter::Delay(d)` within ceiling → `Some(d)`.
  - `Delay(d)` above ceiling → `Some(ceiling)` (clamp).
  - `DateTime(future)` → `Some(future - now)` clamped to ceiling.
  - `DateTime(past)` → `Some(ZERO)`.
  - `LimitExceeded` with `retry_after: None` → `None`.
  - A non-rate-limit `ErrorKind` → `None`.
- `run_sync_loop` honoring a `RateLimited` step (mirror the existing
  `loop_recovers_from_transient_failures` injected-step pattern):
  - A step returning `RateLimited { retry_after: Some(small) }` then `Ok` →
    loop continues, records the rate-limited health (state/field set), then
    recovers to `Healthy`; assert it did **not** treat it as `Fatal`.
  - `RateLimited { retry_after: None }` → falls back to the exponential backoff
    floor (assert via a deterministic/fast `BackoffConfig`).
  - Repeated `RateLimited` → the exponential floor ratchets up (escalation), but
    never below the server value.
- `SyncHealth::record_rate_limited` sets the new field/state and clears it on the
  next `record_success`; `to_json()` still emits valid, token-free JSON
  (extend `health_transitions_and_redacts_nothing`).
- `BackoffConfig` default includes a sane `rate_limit_ceiling`.
- *Optional:* a `matrix.rs` test asserting `build_client*` applies the bounded
  `RequestConfig` (if the SDK exposes it for assertion; otherwise cover by
  construction/compile).

Live/integration: inducing a real homeserver 429 deterministically is not
feasible in the Tuwunel harness, and the repo has no mock-transport
(`wiremock`/`matrix-sdk-test`) infrastructure today. **State this explicitly** in
the spec/PR and rely on the unit coverage of classification + loop handling.
Adding a mock-transport test is optional future work; do not block on it. Run the
standard gate before finishing: `cargo fmt --check`,
`cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all`.

## Documentation Updates

- **`docs/architecture.md` §11.4** — replace the aspirational "daemon backs off,
  chunks less frequently, may switch to artifact mode" row with the implemented
  behavior, e.g.: *the daemon's `/sync` loop honors the homeserver's `Retry-After`
  (clamped, interruptible) to size its backoff; matrix-sdk additionally retries
  individual rate-limited requests honoring `retry_after_ms`; the per-invocation
  stream rate cap and large-output artifact offload are **static** and not driven
  by sync 429s.* Add a one-line "future work" note that dynamically throttling the
  stream / forcing artifact mode on observed 429s is not yet wired (matching the
  Non-Goals here).
- **`docs/architecture.md` §8.3 / §8.4** — soften/clarify the
  "events_per_second exceeds homeserver rate limits → artifact mode" trigger to
  mark it as planned rather than implemented (consistent with §11.4), so the doc
  no longer implies a 429-driven artifact switch exists.
- **`README.md`** — only if the status table’s reliability/sync row needs a touch;
  a small note that sync backoff honors server `Retry-After` is reasonable but not
  required. Do not over-claim stream/artifact 429 behavior.
- Document the new `RequestConfig` choice inline (code doc comment) and, if
  helpful, a sentence in the security-hardening or reliability docs about the
  rate-limit clamp ceiling. No wiki page is strictly required; mirror any
  architecture change’s intent if a relevant `wiki/` page exists.

## Risks and Open Questions

- **Double-backoff / interaction with the SDK (primary design decision).** With
  the SDK's default 15-min internal retry budget, the loop rarely sees a 429.
  *Recommended:* bound `RequestConfig.max_retry_time` (Layer 2, ≈30 s) so
  sustained rate limits surface to the loop, which owns the visible/interruptible
  Retry-After backoff. *Alternative:* `disable_retry()` and let the loop own all
  retry (simplest mental model, but loses the SDK's fast inner retry for momentary
  blips). **Confirm which.** Whichever is chosen, ensure the loop's honored delay
  is never *added on top of* an already-served SDK wait in a way that doubles the
  effective backoff for the operator.
- **Health surface shape.** Additive `rate_limited_secs` field (recommended,
  non-breaking) vs. a new `SyncState::RateLimited` variant (more expressive,
  widens the status enum). Decide before touching the status formatter.
- **HTTP-date `Retry-After` header.** The SDK ignores `RetryAfter::DateTime`;
  honoring it is one of the concrete value-adds of doing this at the loop level.
  Confirm `client_api_error_kind()` actually surfaces the `DateTime` form for a
  429 carrying only a header (vs. only the `retry_after_ms` body) so the
  `DateTime` arm is reachable; if the SDK only ever yields `Delay`, keep the
  `DateTime` arm anyway for safety but note it may be unreachable in practice.
- **`watch.rs` parity.** Honoring `RateLimited` in the `task watch` loop is a
  small, consistent extension. Decide whether to include it in this PR or defer;
  if deferred, note the asymmetry in the PR so it is not mistaken for an
  oversight.
- **Ceiling value.** A 5-minute `rate_limit_ceiling` default is a guess; confirm
  it is acceptable for a long-lived daemon (operators generally prefer the daemon
  to keep retrying rather than give up, so the ceiling caps a *single* wait, not
  total retries).
- **Out-of-scope creep.** Resist wiring the 429 signal into stream throttling /
  artifact mode in this PR (Non-Goal) — the docs reconciliation is the agreed
  treatment for that gap.

## Implementation Checklist

1. Read `sync.rs` end-to-end, `matrix.rs` L160–215, `lifecycle.rs` L330–430,
   `watch.rs` L35–130, and `docs/architecture.md` §8 + §11. Re-read the
   matrix-sdk retry summary above so you don't re-implement the SDK's retry.
2. Add `BackoffConfig.rate_limit_ceiling: Duration` (doc comment; update `Default`
   and the test `fast_backoff()` helper).
3. Add `StepError::RateLimited { retry_after: Option<Duration> }` (doc comment).
4. Add pure `rate_limit_retry_after(kind, now, ceiling)` and
   `is_rate_limit_error(&matrix_sdk::Error)` helpers in `sync.rs`.
5. In `run_matrix_sync_with_subscribers`'s error branch, classify
   fatal → rate-limited → transient, extracting and clamping `retry_after`.
6. Add the `RateLimited` arm to `run_sync_loop`: compute
   `delay = retry_after.unwrap_or(backoff floor).max(backoff floor)`, record
   rate-limited health, `sleep_interruptible`.
7. Add `SyncHealth::record_rate_limited(...)` plus the chosen surface (additive
   field *or* `SyncState::RateLimited`); ensure `record_success` clears it and
   `to_json()` stays token-free.
8. Set a bounded `RequestConfig` (`max_retry_time`) on both `build_client` and
   `build_client_with_store`; document the rationale inline.
9. Re-export any newly public items from `lib.rs` as needed; render any new status
   field/state in the `daemon status` human + `--json` formatters.
10. *(Optional)* Mirror the `RateLimited` handling into `watch.rs`'s `run_watch`.
11. Add the unit tests from the Testing Plan (classifier table, loop handling,
    health JSON, default ceiling). Note in the PR that no live 429 test exists and
    why.
12. Reconcile `docs/architecture.md` §11.4 (and §8.3/§8.4) with the shipped
    behavior; add the "future work" note for 429-driven stream/artifact throttle.
    Touch the README status row only if warranted.
13. Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
    warnings`, `cargo test --all`. Confirm MSRV 1.93 (no newer APIs) and no
    `unsafe`.
