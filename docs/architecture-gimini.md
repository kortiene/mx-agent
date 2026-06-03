# mx-agent Architecture Notes

This file was an alternate architecture draft. Its content has been consolidated into the canonical architecture document:

- [architecture.md](architecture.md)

The canonical document now incorporates the original CLI, Matrix protocol mapping, stream handling, task DAG, daemon/IPC, and security design, plus additional implementation-critical details for:

- event versioning
- cancellation
- large output artifact mode
- backpressure
- stream reliability
- idempotency and reconnect recovery
- approval workflow
- trust bootstrap
- task-state conflict handling
- named tool schemas
- MVP implementation scope

> Note: this filename preserves the original `gimini` spelling for compatibility with existing references. Prefer linking to `architecture.md` in new documentation.
