# Security Policy

`mx-agent` is intended to broker remote execution between autonomous agents. Security reports are taken seriously.

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
