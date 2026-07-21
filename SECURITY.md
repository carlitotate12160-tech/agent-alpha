# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main branch | ✅ Yes |
| other branches | ❌ No |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please send an email to the project maintainers. Your report will be acknowledged within 48 hours, and you'll receive a more detailed response within 7 days indicating the next steps in handling your report.

After the initial reply to your report, the security team will keep you informed of the progress towards a fix and announcement. You may be asked to provide additional information or guidance.

## Security Best Practices

### Deployment Security

- **Database isolation**: PostgreSQL and Redis are bound to `127.0.0.1` only (see `infra/docker-compose.yml`)
- **Secrets management**: All secrets use `SecretsManager` with encryption at rest
- **TLS verification**: Production paths default to `verify=True` for all HTTP clients
- **Authorization gate**: All offensive operations require explicit SOW-based authorization (see `docs/ADR.md` §1)

### Code Security

- **No hardcoded secrets**: All credentials are loaded from environment variables or vault
- **Input validation**: All user inputs are validated via boundary checks (e.g., `valid_engagement_id` regex)
- **Secret redaction**: Sensitive data is redacted before logging or LLM transmission
- **Prompt injection defense**: Strict separation between trusted instructions and untrusted target content

### Dependency Security

- **Container image pinning**: Docker images are digest-pinned to specific versions (see `docs/ADR.md` §12.35)
- **Automated scanning**: Trivy scans run nightly via `.github/workflows/security-audit.yml`
- **Python dependency audit**: `pip-audit` runs on every CI push
- **SAST scanning**: Bandit runs on every CI push

### Known Residual Risks

**Category 1 — No upstream patch (5 CVEs):**

The following CVEs have no upstream patch yet but are mitigated by compensating controls:

- **CVE-2026-32281** (crypto/x509)
- **CVE-2026-32283** (net/url)
- **CVE-2026-33814** (net/mail)
- **CVE-2026-39820** (mime)
- **CVE-2026-42499** (os-symlink)

**Category 2 — Upstream fix exists but image not rebuilt (16 CVEs, suppressed via `.trivyignore`):**

The pinned `pgvector/pgvector:pg16-trixie` image bundles `gosu` with Go 1.24.6. 16 Go stdlib CVEs (1 CRITICAL + 15 HIGH) have fixes in Go 1.25.x+, but the pgvector maintainer has not rebuilt the image. Suppressed via `.trivyignore` with explicit CVE IDs. See ADR §12.35 Decision 3b.

**Compensating control**: The PostgreSQL database is NOT internet-exposed — only the Python application connects on the private network (127.0.0.1 binding). `gosu` is a startup-only privilege helper, not a network service. The Go stdlib DoS surface is not reachable by an external attacker. See `docs/ADR.md` §12.35 for details.

## Security Architecture

For detailed security architecture decisions, see:

- **docs/ADR.md** - Architecture Decision Record, especially:
  - §1: Non-Negotiable Authorization Layer
  - §8l: Platform Security & Data Lifecycle
  - §8n: Reporting Standards & Advanced Rules of Engagement
  - §12.35: pgvector image digest pinning

## Security Testing

- **Unit tests**: All security-critical code has unit tests
- **Integration tests**: Live-fire tests validate security invariants (e.g., `tests/phase_0/test_engagement_id_validation.py`)
- **Penetration testing**: Scheduled penetration testing on self-owned lab environments only
- **CodeQL**: Static analysis runs on every push with justified suppressions only

## Private Key Management

- Private keys are never committed to the repository
- All keys are stored in environment variables or a secrets vault
- Keys are rotated according to organizational policy

## License

This project is licensed under the terms specified in the LICENSE file.

## Questions?

For general security questions that are NOT vulnerability reports, please open a GitHub discussion or issue with the `security` label.
