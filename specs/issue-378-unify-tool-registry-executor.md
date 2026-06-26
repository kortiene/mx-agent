# Unify the named-tool registry and executor dispatch (#378)

## Problem Statement

Tool *declaration* and tool *execution* are two independent sources of truth with
no parity:

- Declaration/advertisement lives in `ToolRegistry` (`crates/mx-agent-daemon/src/tools.rs`).
  `ToolRegistry::builtin()` registers exactly `[run_tests, lint]` via `builtin_tools()`,
  whose schemas are built by `run_tests_tool()` / `lint_tool()`.
- Execution lives in a *separate, hardcoded* `match name { … }` in
  `crates/mx-agent-daemon/src/tool_exec.rs` (`tool_run_spec`), plus a *second* hardcoded
  `match name` in `tool_label`.

Nothing ties the two together, so a tool added to the registry (a future third
built-in, or a custom registry handed to `AgentTools::from_state_with_registry`) is
advertised and resolves on the discovery side but returns `UnknownTool` at call time —
exactly the bug fixed for `lint` in #225, but only by patching one match arm, not by
removing the structural gap.

Separately, `ToolRegistry::resolve()` strips the `@version` suffix and matches by name
only, while the executor only ever receives the bare name. So an advertised
`run_tests@2.0.0` silently runs the `1.0.0` implementation — the version is neither
honored nor rejected.

This is a correctness/maintainability issue, **not** an auth bypass: execution stays
gated by policy `allow_tools` and the resolved `Allowance` (sandbox floor, env scrub,
network deny) exactly as raw `exec` (architecture §13.5). The failure mode is a
misleading capability advertisement and a silent version mismatch, not privilege
escalation.

## Goals

1. Make declaration and execution a **single source of truth**: registering a built-in
   inherently provides its executor (command builder + label), so a registered-but-
   unmatched tool cannot exist. A missing executor must be a compile error or a single
   covered invariant test, never a runtime `UnknownTool`.
2. Collapse the duplicate `tool_label` match into that same source.
3. Decide `@version` explicitly: **reject** an unsupported version with a distinct
   `ToolError::UnsupportedVersion` rather than silently downgrading. A request for the
   supported version (or a bare name with no version) still runs.
4. Add a parity test asserting every `ToolRegistry::builtin()` entry is executable
   (resolves to a runner without `UnknownTool`), so a future registered-but-unmatched
   tool fails CI rather than production.

## Non-Goals

- Re-implementing `lint` (already shipped in #225).
- Implementing multiple concurrent versions of a tool (we ship only `1.0.0`; honoring a
  newer version would require a second implementation — out of scope).
- Changing the discovery-side `ToolRegistry::resolve()` name-only matching (it resolves
  advertised refs for *display*; version enforcement belongs at *execution*).
- A custom/third-party tool execution backend (no new built-ins are added here).
- Any change to the `CallErrorKind` wire enum, IPC surface, CLI flags, or Matrix schemas.

## Relevant Repository Context

- `crates/mx-agent-daemon/src/tools.rs` — `ToolRegistry` (BTreeMap keyed by name),
  `builtin_tools() -> Vec<ToolSchema>`, schema builders `run_tests_tool()`/`lint_tool()`,
  `resolve()` (strips `@version`).
- `crates/mx-agent-daemon/src/tool_exec.rs` — `ToolError {UnknownTool, InvalidArgs, Spawn}`,
  `tool_run_spec` (hardcoded `match name` → command builder + sandbox floor), `tool_label`
  (second hardcoded match), `execute_tool` (sync) / `execute_tool_async` (async),
  `run_tests_command`/`lint_command` argv builders, `summarize`.
- Execution call sites (all pass the wire tool string, which may be `name@version`):
  - live: `call.rs:execute_authorized_call` → `execute_tool_async(&request.tool, …)` —
    maps an error to `CallResponse { ok:false, error: Some(err.to_string()) }` (no match).
  - loopback: `call_ipc.rs:run_loopback_with` → `execute_tool` — matches `ToolError`
    variants onto `CallErrorKind` (exhaustive — **must** gain an arm).
  - task DAG: `task_dispatch.rs` → injectable `run_tool` fn pointer (`execute_tool` by
    default); maps an error via `format!` (no match).
- Discovery: `agent.rs:from_state_with_registry` → `registry.resolve(reference)`.
- `ToolError` is `pub` and re-exported from `lib.rs`; exhaustive matches are only in the
  `Display` impl and `call_ipc.rs`. `Error::source` already has a `_` arm.
- Constraints (preserve): CLI stateless / daemon owns state; no `unsafe`; MSRV 1.93;
  document public APIs; never log secrets; human output + `--json`; Unix-only.

## Proposed Implementation

### Single source of truth (Goal 1, 2)

In `tool_exec.rs`, introduce one canonical built-in table that pairs each tool's identity
+ advertised schema body with its executor. Function pointers and `&'static str` are
`const`-constructible, so the table is a `const` slice — adding an entry without a command
builder is a **compile error**:

```rust
struct BuiltinTool {
    name: &'static str,
    version: &'static str,
    description: &'static str,
    label: &'static str,                                       // collapses tool_label
    command: fn(&Value) -> Result<(String, Vec<String>), ToolError>,
    io_schema: fn() -> (Value, Value),                         // (input_schema, output_schema)
}
const BUILTIN_TOOLS: &[BuiltinTool] = &[
    BuiltinTool { name: RUN_TESTS, version: "1.0.0", description: "Run project test suites",
        label: "cargo test",   command: run_tests_command, io_schema: run_tests_io_schema },
    BuiltinTool { name: LINT,     version: "1.0.0", description: "Run project linters",
        label: "cargo clippy", command: lint_command,      io_schema: lint_io_schema },
];
```

- `BuiltinTool::schema()` assembles the advertised `ToolSchema` from the descriptor
  (single source for name/version/description/io — no duplication).
- `pub(crate) fn builtin_schemas() -> Vec<ToolSchema>` maps the table.
- `tools::builtin_tools()` delegates to `tool_exec::builtin_schemas()`; the schema builders
  `run_tests_tool()`/`lint_tool()` are removed from `tools.rs` (their bodies become the
  `*_io_schema()` fns next to their command builders — the executor now owns the full
  definition). `ToolRegistry`/`resolve` are unchanged.

### Version enforcement (Goal 3)

Add `ToolError::UnsupportedVersion { tool, requested, supported }`. Add:

```rust
fn resolve_builtin(reference: &str) -> Result<&'static BuiltinTool, ToolError>
```

that splits `name@version`, looks up by name (`None` → `UnknownTool(reference)`), and if a
version is present and `!= entry.version` returns `UnsupportedVersion`. `tool_run_spec`
and `tool_label` both go through `resolve_builtin` instead of the hardcoded matches, so a
bare name and the supported version run, and any other version errors clearly.

Mapping at the loopback boundary: `ToolError::UnsupportedVersion` → `CallErrorKind::InvalidArgs`
(exit 64, "invalid usage") — the tool exists but the request asks for a version the daemon
cannot honor. This reuses the existing wire kind (no `CallErrorKind`/IPC change); the
distinct signal is the `ToolError` variant and its message. The live path already surfaces
`err.to_string()`, so the clear message flows through unchanged.

### Parity test (Goal 4)

A unit test iterates `ToolRegistry::builtin()` (and `BUILTIN_TOOLS`) and asserts every entry
resolves to an executor — `resolve_builtin(name)` is `Ok` and `tool_run_spec` never returns
`UnknownTool` — plus `entry.name == entry.schema().name`. Mirrors the existing
`execute_tool_dispatches_lint` regression.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/tool_exec.rs` — descriptor table, `resolve_builtin`,
  `UnsupportedVersion`, rewire `tool_run_spec`/`tool_label`, `*_io_schema`, tests.
- `crates/mx-agent-daemon/src/tools.rs` — `builtin_tools()` delegates; remove
  `run_tests_tool`/`lint_tool`; update two tests that referenced them; doc note on the
  discovery-vs-execution version asymmetry.
- `crates/mx-agent-daemon/src/call_ipc.rs` — add the `UnsupportedVersion` match arm.
- `docs/architecture.md` §5.2 and `docs/cli-reference.md` — document that named-tool
  execution honors the version (mismatch → clear error, not silent downgrade).

## CLI / API Changes

- Public Rust API: new `ToolError::UnsupportedVersion` variant (re-exported via `lib.rs`).
- User-observable: `call --tool run_tests@<other-version>` now returns a clear error
  (exit 64) instead of silently running `1.0.0`. Bare `run_tests` and `run_tests@1.0.0`
  are unchanged. No new flags.

## Data Model / Protocol Changes

None. No Matrix event schema, IPC method, `CallErrorKind`, signing, or persistence changes.

## Security Considerations

- No change to the authorization pipeline (signature → trust → policy → `Allowance` →
  sandbox floor). Execution remains gated by `allow_tools` and the resolved confinement,
  identical to raw `exec`. The fix is fail-closed: an unknown tool or unsupported version
  is rejected before any process spawns.
- No secrets logged; error messages carry only tool/version strings (no args/env).
- Unix-only, no `unsafe`, MSRV-safe (const fn-pointer table, no new deps).

## Testing Plan

- `tool_exec.rs`: parity test (every built-in is executable); `@version` tests
  (bare ok, matching version ok, mismatched → `UnsupportedVersion`); `Display` for the new
  variant; existing unknown/invalid-args tests still pass unchanged.
- `tools.rs`: `builtin_tools()`/`qualified_refs`/`resolve` tests still pass; update
  `register_replaces_by_name` to source its base schema from `builtin_tools()`.
- `call_ipc.rs`: a loopback test that an unsupported version maps to
  `CallErrorKind::InvalidArgs`.
- Full gates: `cargo fmt --check`, `cargo clippy --all-targets --all-features -D warnings`,
  `cargo test --all`, `cargo build --all`.

## Documentation Updates

- `docs/architecture.md` §5.2: one sentence — named-tool execution honors the advertised
  version; an unsupported version returns a clear error rather than silently downgrading.
- `docs/cli-reference.md`: note the same on the `call`/`--tool` surface.

## Risks and Open Questions

- Exit-code mapping for `UnsupportedVersion`: chosen `InvalidArgs`/64 (usage error) over
  127 (not-found) because the tool exists; documented so it is not surprising.
- A `const` table requires `command`/`io_schema` to be plain `fn` items (already are). No
  closure capture is needed.
- Decision is **reject**, not honor — revisit only if multiple tool versions ship.

## Implementation Checklist

1. `tool_exec.rs`: add `BuiltinTool` + `const BUILTIN_TOOLS` + `BuiltinTool::schema()` +
   `builtin_schemas()`; add `run_tests_io_schema`/`lint_io_schema` (bodies from the old
   `*_tool` schema builders).
2. `tool_exec.rs`: add `ToolError::UnsupportedVersion { tool, requested, supported }` +
   `Display` arm; `Error::source` `_` arm already covers it.
3. `tool_exec.rs`: add `resolve_builtin`; rewrite `tool_run_spec` and `tool_label` through it.
4. `tools.rs`: `builtin_tools()` → `tool_exec::builtin_schemas()`; delete `run_tests_tool`/
   `lint_tool`; fix `register_replaces_by_name`; doc the version asymmetry on `resolve`.
5. `call_ipc.rs`: map `ToolError::UnsupportedVersion` → `CallErrorKind::InvalidArgs`.
6. Add parity + `@version` + loopback tests.
7. Docs: architecture §5.2 + cli-reference version note.
8. Run fmt/clippy/test/build; fix; self-review; commit `closes #378`; PR; CI; merge.
