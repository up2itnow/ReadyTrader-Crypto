## Security Policy

### Reporting a Vulnerability
If you believe you have found a security vulnerability, **do not** open a public issue.

Please report details privately with:
- **Description** of the issue
- **Reproduction steps**
- **Impact** assessment
- Any relevant **logs** or **screenshots** (redact secrets)

### Scope Notes
- This project can be configured for **live trading** (`PAPER_MODE=false`). Keep secrets out of source control.
- This project uses a **signer abstraction**; prefer keystore-based signing over raw private keys.

