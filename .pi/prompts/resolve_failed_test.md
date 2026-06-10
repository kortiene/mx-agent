---
description: Resolve failing repository checks reported by the phased ADW test gate
argument-hint: "<failing-output-and-context>"
---
The repository's test/verification gate is failing. Fix the failures.

Failing output and context (truncated):

$ARGUMENTS

## Instructions

- Investigate the failures above and make the smallest correct change that fixes them.
- Fix the root cause in the code or the tests as appropriate. Do NOT weaken or delete
  meaningful assertions, skip tests, or mask failures to make the gate pass.
- Stay within the scope of the current change; do not start unrelated work.
- Preserve mx-agent constraints: no `unsafe` Rust, MSRV 1.74, daemon/CLI separation, no
  secrets in code/logs/output, Unix-only.
- The orchestrator re-runs the gate after you finish. Report how many failing checks you
  fixed (`resolved`) and how many remain (`remaining`); if you could fix nothing, say so via
  the counts so the loop can stop.

## Verify before finishing

If you changed Rust code, before you report:

- Run `cargo fmt` so your edits are formatted. The Python finalize step runs `cargo fmt --check`
  as a pre-merge gate and aborts the whole run (no commit, no PR) on any unformatted line, so this
  is not optional.
- Run `cargo clippy --all-targets --all-features -- -D warnings`.
- Run `cargo test --all` (or the package(s) you touched, then the full suite if practical).
- Run `cargo build --all`.

Fix anything these surface and rerun the relevant check. If a check cannot be run, say why and
give the exact command.
