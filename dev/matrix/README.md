# Local Matrix homeserver (dev / e2e)

A throwaway [Tuwunel](https://github.com/matrix-construct/tuwunel) homeserver in
Docker for local development and the integration/e2e tests (issues #59–#61).
Tuwunel is a single-binary Rust homeserver that starts in a few seconds, which
keeps the test loop fast compared to Synapse.

> **Scope:** this homeserver is for local testing only. It binds to `127.0.0.1`,
> has federation disabled, and its registration token lives in a gitignored
> `dev/matrix/.env`. Do not use it as a real deployment, and do not point it at
> production data.

## Requirements

- Docker with Compose v2 (`docker compose`)
- `curl` and `jq` (used by the helper script)

## Quick start

```bash
# Start the homeserver (auto-creates dev/matrix/.env with a random token).
scripts/matrix_dev.sh up

# Register a test user; prints {user_id, device_id, access_token, home_server}.
scripts/matrix_dev.sh register alice

# Log in an existing user (fresh token / device).
scripts/matrix_dev.sh login alice

# Other commands.
scripts/matrix_dev.sh status      # is it up? prints the base URL
scripts/matrix_dev.sh url         # http://127.0.0.1:8008
scripts/matrix_dev.sh logs        # follow homeserver logs
scripts/matrix_dev.sh down        # stop (keeps data)
scripts/matrix_dev.sh reset       # stop and wipe all data (fresh state)
```

User IDs are `@<name>:localhost`; clients connect to `http://127.0.0.1:8008`.

## Using it with the daemon

Point the daemon's Matrix config at the local homeserver:

```toml
[matrix]
homeserver_url = "http://127.0.0.1:8008"
```

Then log in with a registered user, e.g.:

```bash
MX_AGENT_PASSWORD=alice-pass mx-agent auth login --homeserver http://127.0.0.1:8008 --user alice
```

## Configuration

- `dev/matrix/docker-compose.yml` — the Tuwunel service (loopback-only port,
  named data volume).
- `dev/matrix/tuwunel.toml` — homeserver config (no secrets).
- `dev/matrix/.env` — local config incl. `MATRIX_REGISTRATION_TOKEN` and
  `MATRIX_PORT`. Auto-created from `.env.example`; **gitignored**.

## CI note

The same `scripts/matrix_dev.sh up` flow runs under Docker in CI, so the planned
integration-test job (issue #60) can stand up the homeserver, register users,
and exercise the daemon against it. The Rust integration tests and the CI job
itself are implemented in their own issues; this directory provides the
homeserver harness they build on.
