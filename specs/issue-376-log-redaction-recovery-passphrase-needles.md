# Add `recovery`/`passphrase`/bare-`key` needles to the log-redaction backstop and document `Secret` as the primary guarantee

Issue: #376 (`type:security`, `area:security`, `priority:p2`). Follow-up to #311 (CLOSED), which built the telemetry field-redaction layer and `Secret`-wrapped `RecoverParams.recovery_key` / `RecoveryEnableResult.recovery_key`.

## Problem Statement

The telemetry field-redaction backstop shipped in #311 masks a structured log field's **value** when its **key name** looks sensitive, matched by `mx_agent_telemetry::is_sensitive_key` (`crates/mx-agent-telemetry/src/lib.rs:265-280`). The needle list is name-only and omits the recovery surface: `is_sensitive_key("recovery_key")`, `is_sensitive_key("recovery")`, and `is_sensitive_key("passphrase")` all return `false`, because none of `token`/`secret`/`password`/`passwd`/`api_key`/`apikey`/`access_key`/`private_key`/`credential`/`authorization` is a substring of those names.

This is currently safe **only** because the recovery key is always wrapped in a redacting `Secret` before it can reach a `tracing` call — the real no-secrets-in-logs guarantee is the `Secret` wrapper (`crates/mx-agent-daemon/src/recovery_ipc.rs:23-29`, `crates/mx-agent-daemon/src/verification.rs:103`/`340-346`), not the needle set. The needle set is a backstop that happens not to cover the recovery-key field name. The current `init` doc-comment frames the redactor as "the operational-log counterpart to the `Secret` wrapper" (`lib.rs:89-94`), which can be misread as making field-name redaction load-bearing when it is only a safety net.

The gap is a latent future-regression footgun, not an active leak: a developer who later writes `tracing::debug!(recovery_key = %exposed)` or `tracing::info!("recovered with {key}")` would leak in the clear, because (1) `recovery_key` is not a needle and (2) format-message interpolation is never scanned by the visitor (`lib.rs:138-141`). This issue asks to (a) extend the needle set so the backstop also covers `recovery`/`passphrase`/bare-`key` field names, and (b) document explicitly that `Secret<T>`/`session::Secret` is the **primary** guarantee and field-name redaction is only a **backstop**, so no future code interpolates a secret into a format message and trusts the redactor.

## Goals

- `is_sensitive_key("recovery_key")`, `is_sensitive_key("recovery")`, and `is_sensitive_key("passphrase")` return `true`, proven by extending the existing `detects_sensitive_keys` unit test (`lib.rs:434-450`).
- A bare-`key` heuristic catches field names literally named `key` or ending in `_key` (e.g. `signing_key`, `device_key`, `recovery_key`) **without** over-matching innocuous names that merely contain the letters `key` (`keyspace`, `monkey`, `key_count`, `key_id`), proven by a dedicated negative test that pins the chosen boundary rule.
- The `is_sensitive_key` doc-comment (`lib.rs:261-264`) and `docs/security-hardening.md` state plainly that `Secret<T>`/`session::Secret` is the **primary** no-secrets-in-logs guarantee and field-name redaction is a **backstop** — explicitly: do not interpolate a secret into a format message and rely on the redactor.
- No production secret-handling code path changes: the recovery key stays `Secret`-wrapped (`recovery_ipc.rs:23-29`, `verification.rs:103`); the cleartext still only exists at the SDK call site (`verification.rs:351-362`).
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and the telemetry + daemon (audit/runner) unit tests stay green.

## Non-Goals

- **No scanning of format-message interpolation.** The `message` pseudo-field stays untouched (`lib.rs:138-141`); the value-by-key model is unchanged. The fix is to widen the needle set and document the limitation, not to add string-content scanning (which would be slow, lossy, and is explicitly the wrong layer — `Secret` is the right one).
- **No value-based detection.** Redaction stays keyed on the field/flag/env-var *name*, never on inspecting the value (no entropy heuristics, no regex over values).
- **No new redaction taxonomy or separate needle list.** Extend the single shared `is_sensitive_key`; do not fork a telemetry-only list (the audit redactor and env scrub deliberately reuse the same predicate — see Security Considerations).
- **No change to how secrets are stored at rest or wrapped.** `Secret<T>` / `session::Secret`, `RecoverParams`, `RecoveryEnableResult`, and `recover()`'s exposed-`&str` call site are correct and stay as-is.
- **No CLI/IPC/protocol/schema changes**, no Windows support, no `unsafe`, no MSRV bump (stays 1.93; nothing here uses post-1.93 APIs).
- **Not changing** the audit-log argv redactor's two-shape masking logic (`redact_command`) or the env-scrub allowlist model — only the shared predicate they call widens, and that effect is intentional defence-in-depth (documented below).

## Relevant Repository Context

**Owning crate.** `crates/mx-agent-telemetry` owns subscriber setup plus the `Secret<T>` / `is_sensitive_key` / `redact` helpers (root `Cargo.toml` workspace member; depends only on `tracing` + `tracing-subscriber`). The needle change lands entirely in `crates/mx-agent-telemetry/src/lib.rs`.

**`is_sensitive_key` is a shared predicate with three production callers** — this is the most important fact for sizing the change:

1. **Telemetry field redaction** (the intended target). `RedactingVisitor` redacts a field's value when `is_sensitive_key(field.name())` (`lib.rs:147-170`), installed by `init` for the human formatter via `Redacting(DefaultFields::new())` (`lib.rs:107-109`) and for JSON via the `RedactingJson` event formatter over `RedactingVisitor(JsonVisitor::new(..))` (`lib.rs:100-103`, `lib.rs:194-241`). The `message` pseudo-field is never sensitive by name, so messages are untouched (`lib.rs:138-141`).
2. **Audit argv redactor.** `redact_command` (`crates/mx-agent-daemon/src/audit.rs:532-555`) masks `KEY=value` / `--flag=value` and `--flag value` shapes when `is_sensitive_key(&normalize_key(key))` is true; `normalize_key` strips leading dashes and maps `-`→`_` so `--api-key` matches `api_key` (`audit.rs:557-561`). Widening the needle set widens what the audit trail masks (fail-safe).
3. **Child-process env scrub.** `is_secret_var` ORs `mx_agent_telemetry::is_sensitive_key(name)` into the secret predicate (`crates/mx-agent-daemon/src/runner.rs:110-114`); `sanitize_env` drops any name that is `is_secret_var`, even an allowlisted one, as defence-in-depth, and the remote `exec.request` override screen rejects override keys of sensitive shape (`runner.rs:1038-1057`). Widening the needle set widens what is scrubbed/rejected (fail-safe).

**Why the recovery key is already safe (do not change).**
- `RecoverParams.recovery_key: session::Secret` (`recovery_ipc.rs:23-29`); `Secret` is `#[serde(transparent)]` so it still round-trips as a bare JSON string for IPC, while `Debug` renders `Secret(***redacted***)`.
- `RecoveryEnableResult.recovery_key: session::Secret`, built via `Secret::new(...)` (`verification.rs:100-106`, `verification.rs:338-348`); `recover()` consumes the **exposed** `&str` (`verification.rs:69`, `verification.rs:351-362`), so cleartext exists only at the SDK call site, never in a `Debug`-formattable struct field.
- `session::Secret` redacts `Debug`/`Display` (`crates/mx-agent-daemon/src/session.rs:34`, `48-58`); the generic telemetry `Secret<T>` does the same (`lib.rs:296-326`). Both render `***redacted***`.
- Existing tests prove safety comes from `Secret`, not the needle set: `recover_params_debug_redacts_key` (`recovery_ipc.rs:92-108`) and `recovery_key_is_redacted_in_debug` (`verification.rs:609-624`).

**Conventions.** `missing_docs` is a CI-enforced warning (document any new public item; here the only public surface is the already-documented `is_sensitive_key`, whose doc-comment expands). `unsafe` is forbidden. Tests live inline in `#[cfg(test)] mod tests`. Logs go to stderr; human is the default format, JSON via `MX_AGENT_LOG_FORMAT=json`.

## Proposed Implementation

### 1. Widen the needle set with a token-bounded bare-`key` rule (`lib.rs:265-280`)

Add `recovery` and `passphrase` as substring needles, and add a bare-`key` heuristic matched only on a token boundary:

```rust
pub fn is_sensitive_key(key: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "token",
        "secret",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "credential",
        "authorization",
        "recovery",   // recovery_key, recovery_passphrase, recovery_code
        "passphrase",
    ];
    let lower = key.to_ascii_lowercase();
    NEEDLES.iter().any(|needle| lower.contains(needle))
        // Bare `key`, on a token boundary only: the whole name is `key`, or it
        // ends in `_key` (e.g. `signing_key`, `device_key`, `recovery_key`).
        // Deliberately NOT a raw `contains("key")`, which would also redact
        // `keyspace`, `monkey`, `key_count`, and `key_id`.
        || lower == "key"
        || lower.ends_with("_key")
}
```

**Recommended boundary rule: exact `key` OR `_key` suffix.** This is the decision the issue asks the spec to make and pin. Rationale for *not* also matching a `key_` prefix (i.e. `key_*`): the false-positive set for `key_*` (`key_count`, `key_id`, `key_index`, `key_name` — all metadata *about* a key, not key material) is larger and more common than its true-positive set, so including it would over-redact useful audit argv and silently drop benign `key_*` env vars. The `_key` suffix is the idiomatic "this field holds a key" shape and is exactly what `recovery_key`/`signing_key`/`device_key`/`private_key`/`access_key` use. Compound names like `recovery_passphrase` or `my_recovery_key_v2` are caught by the `recovery` substring needle regardless of the boundary rule.

Verify the rule against every acceptance case:

| Name | `recovery`/`passphrase` substring | `== "key"` | `ends_with("_key")` | Result |
|---|---|---|---|---|
| `recovery_key` | ✅ (`recovery`) | — | ✅ | **sensitive** |
| `recovery` | ✅ | — | — | **sensitive** |
| `passphrase` | ✅ | — | — | **sensitive** |
| `key` | — | ✅ | — | **sensitive** |
| `signing_key` | — | — | ✅ | **sensitive** |
| `keyspace` | — | — | — | not sensitive |
| `monkey` | — | — | — | not sensitive |
| `key_count` | — | — | — | not sensitive |
| `key_id` | — | — | — | not sensitive |
| existing positives (`token`, `GITHUB_TOKEN`, `access_token`, `Authorization`, `api_key`, `user_password`, `private_key`) | unchanged | | | **sensitive** |
| existing negatives (`name`, `room`, `agent`, `cwd`, `count`) | unchanged | | | not sensitive |

### 2. Reframe the documentation: `Secret` primary, needle redaction backstop

**`is_sensitive_key` doc-comment (`lib.rs:261-264`).** Replace with explicit primary-vs-backstop framing and the boundary rule, e.g.:

```rust
/// Returns true if `key` names an obviously sensitive field.
///
/// This is a **backstop, not the primary guarantee.** The real no-secrets-in-logs
/// guarantee is the [`Secret`] wrapper (and the daemon's `session::Secret`), whose
/// `Debug`/`Display` always render [`REDACTED`]. Field-name redaction only catches
/// a value recorded under a recognised key; it does **not** scan a format
/// message's interpolated text, nor a secret recorded under an unrecognised key.
/// Never interpolate a secret into a `tracing` message (`debug!("key={k}")`) and
/// rely on this function to catch it — wrap the secret in [`Secret`] instead.
///
/// Matching is case-insensitive. Most needles match as a substring (so
/// `GITHUB_TOKEN`, `access_token`, `Authorization`, `recovery_key`, and
/// `recovery_passphrase` are caught). A bare `key` matches only on a token
/// boundary — the whole name is `key`, or it ends in `_key` — so `signing_key`
/// and `recovery_key` are redacted while `keyspace`, `monkey`, `key_count`, and
/// `key_id` are not.
```

**`init` redaction-backstop comment (`lib.rs:89-94`).** Soften "the operational-log counterpart to the `Secret` wrapper" to make the dependency direction unambiguous — the field redactor sits *behind* `Secret`, not beside it. Suggested: "This is a backstop *behind* the [`Secret`] wrapper (which is the primary guarantee): a stray `tracing::debug!(token = …)` can no longer leak a credential in the clear, but code must still wrap secrets in [`Secret`] and must not interpolate them into a format message, which this layer does not scan."

**`RedactingVisitor` doc (`lib.rs:134-141`)** already notes "the `message` pseudo-field is never sensitive by name, so log messages are untouched"; optionally extend it to add "— so a secret interpolated into a format message is **not** redacted here; wrap it in [`Secret`]."

**`docs/security-hardening.md`** — in the "Tokens never leak into output" paragraph of the *Token isolation model* section (`docs/security-hardening.md:178-185`):
- State that `Secret`/`session::Secret` is the **primary** guarantee and the field-name redactor is a **backstop** (the paragraph already says "a safety net, not a licence to log secrets" — sharpen it to name the do-not-interpolate-into-messages rule explicitly).
- Extend the inline needle examples to include `recovery`, `passphrase`, and `…_key`.
- Optionally add the same primary/backstop note to the *Audit logging* "Operational logs" paragraph (`docs/security-hardening.md:686-692`), which already says "The same secret-key redaction applies to structured fields here."

### 3. Fix the now-stale comment in the env scrub (`runner.rs:70-75`)

The `SECRET_VARS` comment currently justifies the explicit `MX_AGENT_RECOVERY_KEY` entry with "the recovery key matches no needle, so the explicit entry is required." After adding the `recovery` needle, `MX_AGENT_RECOVERY_KEY` **does** match `is_sensitive_key` (it contains `recovery`). Keep the explicit `SECRET_VARS` entry (belt-and-suspenders; it does not depend on telemetry needle tuning), but update the comment so it is no longer false — e.g. "Both are now also caught by `is_sensitive_key` (`password`/`recovery` needles); the explicit entries are retained as a stable, telemetry-independent guarantee." Optionally refresh the `is_secret_var` doc-comment example list (`runner.rs:101-109`).

> No behavioural change is required in `runner.rs`/`audit.rs` — only a comment refresh — but the implementer must run the daemon test suites because both call `is_sensitive_key`.

## Affected Files / Crates / Modules

- **`crates/mx-agent-telemetry/src/lib.rs`** — widen `is_sensitive_key` (`265-280`); rewrite its doc-comment (`261-264`); tighten the `init` backstop comment (`89-94`) and optionally the `RedactingVisitor` doc (`134-141`); extend tests `detects_sensitive_keys` (`434-450`) and add a bare-`key` negative test. **Primary change.**
- **`crates/mx-agent-daemon/src/runner.rs`** — comment-only: refresh the `SECRET_VARS` recovery-key comment (`70-75`) and optionally the `is_secret_var` doc (`101-109`). No logic change. (Read `secret_vars_are_recognised` `735-749` and `non_secret_vars_are_kept` `751-757` to confirm no assertion flips.)
- **`crates/mx-agent-daemon/src/audit.rs`** — no change; read `redact_command` (`532-561`) and its tests (`608-624`) to confirm widening does not break a "preserved" assertion.
- **`docs/security-hardening.md`** — primary/backstop wording + needle-list mention (`178-185`, optionally `686-692`).
- **`README.md`** (optional) — the *Logging* section already says the field redactor is "a backstop" (`README.md:208-214`); no change needed unless aligning wording.

## CLI / API Changes

None. `is_sensitive_key` keeps its `pub fn(&str) -> bool` signature; only its return value for `recovery`/`passphrase`/`*_key`/`key` names changes, and only its doc-comment expands. No new public items, no flags, no IPC methods.

## Data Model / Protocol Changes

None. No event schema, persistence, policy, or serialization change. `RecoverParams` / `RecoveryEnableResult` serde shapes are untouched (`Secret` stays `#[serde(transparent)]`).

## Security Considerations

- **Primary guarantee is `Secret`, backstop is the needle set — and this fix documents exactly that.** The change must not be read as making field-name redaction load-bearing; the whole point is to widen the safety net *and* write down that it is a net.
- **Blast radius is intentional and fail-safe.** `is_sensitive_key` is shared by the audit argv redactor and the child-env scrub. Widening it can only *increase* what those mask/scrub/reject — it never exposes anything previously hidden:
  - *Audit redactor:* `--recovery-key=…`, `passphrase=…`, and `--signing-key …` flag values now get masked in `audit.log` argv. Desirable.
  - *Env scrub:* env var names containing `recovery`/`passphrase`, exactly `KEY`, or ending in `_KEY` are now dropped from child processes and rejected as remote `exec.request` overrides. Desirable for defence-in-depth (e.g. `MX_AGENT_RECOVERY_KEY` is now caught by shape too).
- **Accepted over-redaction edge in the env path.** Because the env scrub drops even *allowlisted* names that match the predicate (with no force-include override), a benign allowlisted var ending in `_KEY` (e.g. `CACHE_KEY`, `IDEMPOTENCY_KEY`) would now be dropped from spawned children. This is fail-safe (a missing env var degrades a command, it never leaks) and is the price of the bare-`key` heuristic; the `_key`-suffix boundary keeps the common cases (`KEY_COUNT`, `KEY_ID`) safe. Called out as an Open Question for sign-off.
- **No production secret-handling code changes.** The recovery key stays `Secret`-wrapped end to end; `recover()` still consumes an exposed `&str` only at the SDK boundary. The daemon/CLI separation, signing, trust, policy, and the `auth`/`trust` same-UID carve-out are untouched.
- **Unix-only, no `unsafe`, no new deps.** Pure logic + docs in a leaf crate.

## Testing Plan

All in `crates/mx-agent-telemetry/src/lib.rs` `#[cfg(test)] mod tests` unless noted.

- **Extend `detects_sensitive_keys` (`lib.rs:434-450`)** — add to the positive loop: `recovery_key`, `recovery`, `passphrase`, `recovery_passphrase`, `signing_key`, `key`, `KEY` (case-insensitivity). Keep the existing positives and the existing negative loop (`name`, `room`, `agent`, `cwd`, `count`) — all still pass.
- **Add a bare-`key` negative test** (e.g. `bare_key_heuristic_avoids_false_positives`) — assert `!is_sensitive_key(x)` for `keyspace`, `monkey`, `key_count`, `key_id`, `keyfile`, `keyring`; this pins the chosen `==key`/`_key`-suffix boundary so a future broadening to raw `contains("key")` fails the test.
- **Keep the subscriber round-trip tests green** — `human_subscriber_redacts_sensitive_event_fields` and `json_subscriber_redacts_sensitive_event_fields` (`lib.rs:367-423`) are unaffected (they use `token`); optionally add an assertion that a `recovery_key = "…"` field renders `***redacted***` through the live human/JSON subscriber to prove the widened needle flows end-to-end through the visitor, not just the predicate.
- **Run the daemon suites that share the predicate** — `cargo test -p mx-agent-daemon` to confirm `secret_vars_are_recognised`/`non_secret_vars_are_kept`/`sanitize_env_*` (`runner.rs:735-…`) and `redact_command` audit tests (`audit.rs:608-624`) still pass under the widened predicate (verified by inspection: none of their asserted names — `PATH`/`HOME`/`LANG`/`CARGO_HOME`/`--name=prod` — match the new rule).
- **No new live/Tuwunel test needed** — this is a pure-logic + docs change; the existing `Secret`-redaction tests (`recovery_ipc.rs:92-108`, `verification.rs:609-624`) already cover the real guarantee.
- **Gates:** `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test -p mx-agent-telemetry -p mx-agent-daemon`.

## Documentation Updates

- `crates/mx-agent-telemetry/src/lib.rs` — `is_sensitive_key` doc-comment (primary/backstop + boundary rule); `init` backstop comment; optional `RedactingVisitor` doc note about message interpolation.
- `docs/security-hardening.md` — *Token isolation model* "Tokens never leak into output" paragraph (`178-185`): primary/backstop wording, do-not-interpolate rule, extend needle examples with `recovery`/`passphrase`/`…_key`; optionally the *Audit logging* operational-logs note (`686-692`).
- `crates/mx-agent-daemon/src/runner.rs` — refresh the now-stale `SECRET_VARS` recovery-key comment (`70-75`) and optionally the `is_secret_var` doc example list.
- `README.md` — no change required (the *Logging* section already calls the field redactor "a backstop"); align wording only if convenient.
- No README status-table change (the "Structured logging, secret redaction" row stays ✅; behaviour is hardened, not newly added — do not imply a new capability).

## Risks and Open Questions

- **Boundary-rule decision (recommended, needs sign-off):** match bare `key` as `== "key" || ends_with("_key")`, treating `key_count`/`key_id`/`keyspace`/`monkey` as **not** sensitive. The issue lists `key_`/`_key`/exact-`key` as candidate boundaries and asks the spec to pin one; this spec recommends *excluding* the `key_` prefix to avoid over-redacting key-metadata names. If reviewers prefer also catching `key_*`, update the negative test accordingly (it would then redact `key_count`).
- **Env-scrub over-redaction (accepted, needs sign-off):** widening the shared predicate drops allowlisted child-env vars ending in `_KEY`/containing `recovery`/`passphrase` (e.g. `CACHE_KEY`), with no force-include override. Fail-safe but could surprise an operator. Acceptable because (a) it only ever removes data from a child, never leaks, and (b) the `_key`-suffix boundary spares the common metadata names. Decision: accept; document the bare-`key` shape in `is_secret_var`'s doc.
- **Keep vs drop the explicit `MX_AGENT_RECOVERY_KEY` SECRET_VARS entry:** recommend **keep** (telemetry-independent guarantee) and only fix the misleading comment. Dropping it would couple the recovery-key scrub to needle-list tuning.
- **Message interpolation remains unscanned by design.** The fix narrows but does not close the footgun for `tracing::info!("recovered with {k}")` where `k` is a raw `&str`. The documentation change is the mitigation; the structural guarantee remains "wrap secrets in `Secret`." No code change attempts value/message scanning.

## Implementation Checklist

1. [ ] In `crates/mx-agent-telemetry/src/lib.rs`, add `"recovery"` and `"passphrase"` to the `NEEDLES` array and append the bounded bare-`key` clause (`lower == "key" || lower.ends_with("_key")`) to `is_sensitive_key` (`lib.rs:265-280`).
2. [ ] Rewrite the `is_sensitive_key` doc-comment (`lib.rs:261-264`): `Secret` is the **primary** guarantee, field-name redaction is a **backstop**, message interpolation is not scanned, and document the case-insensitive substring + `_key`-boundary rule.
3. [ ] Tighten the `init` backstop comment (`lib.rs:89-94`) so the field redactor reads as sitting *behind* `Secret`; optionally extend the `RedactingVisitor` doc (`lib.rs:134-141`) re: message interpolation.
4. [ ] Extend `detects_sensitive_keys` (`lib.rs:434-450`) with positives `recovery_key`/`recovery`/`passphrase`/`recovery_passphrase`/`signing_key`/`key`/`KEY`; add a dedicated negative test asserting `keyspace`/`monkey`/`key_count`/`key_id`/`keyfile`/`keyring` are **not** sensitive.
5. [ ] (Optional but recommended) Add an end-to-end subscriber assertion that a `recovery_key` field renders `***redacted***` in both human and JSON output, mirroring the existing `token` tests.
6. [ ] Update the stale `SECRET_VARS` comment in `crates/mx-agent-daemon/src/runner.rs:70-75` (and optionally the `is_secret_var` doc at `101-109`) so it no longer claims the recovery key "matches no needle"; keep the explicit entries.
7. [ ] Update `docs/security-hardening.md` (`178-185`, optionally `686-692`): primary/backstop framing, the do-not-interpolate rule, and `recovery`/`passphrase`/`…_key` in the needle examples.
8. [ ] Run `cargo test -p mx-agent-telemetry -p mx-agent-daemon` and confirm the audit (`audit.rs:608-624`) and env-scrub (`runner.rs:735-…`) tests still pass under the widened predicate.
9. [ ] Run `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings`; confirm green.
10. [ ] Confirm no production secret-handling code changed (`recovery_ipc.rs:23-29`, `verification.rs:103`/`351-362` untouched) and no README status-table row changed.
