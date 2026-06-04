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

## Integration test

The daemon's Matrix integration test
(`crates/mx-agent-daemon/tests/matrix_integration.rs`) drives the real login,
session-restore, `/sync`, and event-handling paths against this homeserver. It
is `#[ignore]`d so the default `cargo test --all` (which has no homeserver)
stays green. Run it end to end with the harness:

```bash
scripts/matrix_integration_test.sh            # boots the homeserver, runs the test
scripts/matrix_integration_test.sh --teardown # also stops the homeserver afterward
```

The script boots the homeserver, registers two test users, and runs the test
with the env vars it expects (`MX_AGENT_TEST_HOMESERVER`, `MX_AGENT_TEST_USER*`,
`MX_AGENT_TEST_PASSWORD*`). The test creates a room as the second user, has the
daemon user join and sync, and asserts the daemon observes the message.

The same harness also runs the E2EE coverage test (issue #61), which exercises
the daemon against **end-to-end encrypted** rooms: it asserts the daemon
decrypts signed `exec`/`call` requests and authorizes them, and that a
privileged event the daemon cannot decrypt (one sent before it joined) stays an
opaque `m.room.encrypted` event, never reaching authorization — so it is not
executed. The daemon's `e2e-encryption` support is enabled only for test builds
(a `[dev-dependencies]` feature in `crates/mx-agent-daemon/Cargo.toml`), so
`cargo build --all` stays free of the crypto stack.

## Configuration

- `dev/matrix/docker-compose.yml` — the Tuwunel service (loopback-only port,
  named data volume).
- `dev/matrix/tuwunel.toml` — homeserver config (no secrets).
- `dev/matrix/.env` — local config incl. `MATRIX_REGISTRATION_TOKEN` and
  `MATRIX_PORT`. Auto-created from `.env.example`; **gitignored**.

## CI note

The `matrix-integration` job in `.github/workflows/ci.yml` runs
`scripts/matrix_integration_test.sh --teardown` on the Docker-enabled GitHub
runner: it stands up this homeserver, registers users, and exercises the daemon
against it. The same flow runs locally via the command above.
