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
