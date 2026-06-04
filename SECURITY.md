# Security Policy

`mx-agent` is intended to broker remote execution between autonomous agents. Security reports are taken seriously.

For configuring `mx-agent` safely — token isolation, trust bootstrap, policy examples, sandbox configuration, and audit logging, with the safe defaults and unsafe options for each — see the [security hardening guide](docs/security-hardening.md).

## Reporting a Vulnerability

Please do not open a public issue for suspected vulnerabilities. Use GitHub private vulnerability reporting for this repository:

https://github.com/kortiene/mx-agent/security/advisories/new

Include, when possible:

- affected commit or version
- impact
- reproduction steps
- relevant configuration
- whether Matrix tokens, device keys, signing keys, or remote execution policy are involved

## Security-Critical Areas

- Matrix access token isolation
- E2EE/device key storage
- mx-agent signing and verification
- replay protection
- local daemon IPC authentication
- policy bypasses
- sandbox escapes
- remote code execution behavior
- logs or terminal output leaking secrets
