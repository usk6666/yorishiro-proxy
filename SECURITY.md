# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in yorishiro-proxy, please report it
responsibly using one of the following methods:

1. **GitHub Security Advisories** (preferred):
   Go to the [Security Advisories](https://github.com/usk6666/yorishiro-proxy/security/advisories/new)
   page and create a new advisory.

2. **Email**: Contact the maintainer directly via the email listed in the
   Git commit history.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Scope

This security policy covers vulnerabilities in yorishiro-proxy itself, including:

- The proxy engine and protocol handlers
- The MCP server and tool implementations
- TLS/CA certificate handling
- Session storage and data handling
- The web UI

**Note**: yorishiro-proxy is a security testing tool designed to intercept and
analyze network traffic. Reports about the tool's intended functionality
(e.g., "it can intercept HTTPS traffic") are not security vulnerabilities.

### Response Timeline

This project is currently maintained by a single developer. Response times
may vary depending on availability.

- **Acknowledgment**: Best effort, typically within a few weeks
- **Fix release**: Depends on severity and complexity

### Disclosure

We follow coordinated disclosure. Please allow reasonable time for a fix
before public disclosure. We will credit reporters in the release notes
unless anonymity is requested.

## Supported Versions

As the project is in active development, security fixes are applied to the
latest release only.

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| Older   | No        |
