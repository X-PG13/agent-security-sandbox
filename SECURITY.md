# Security Policy

## Scope

Agent Security Sandbox (ASB) is a **research framework** for studying indirect prompt injection attacks and defenses. The mock tools included in this repository do **not** perform real file operations, send real emails, or make real API calls. All tool interactions are simulated.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. **Email**: Send a description to the repository maintainer via GitHub (open a private security advisory).
2. **GitHub Security Advisory**: Use the [Security Advisories](https://github.com/X-PG13/agent-security-sandbox/security/advisories) feature to report privately.
3. **Do not** open a public issue for security vulnerabilities.

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days.

## Responsible Use

This framework is intended for **defensive research** purposes:

- Evaluating and improving AI agent security
- Benchmarking defense strategies against prompt injection
- Academic research and reproducible experiments

**Do not** use the attack cases or injection techniques from this benchmark to target production systems without explicit authorization.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |
