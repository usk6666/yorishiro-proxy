# Contributing to yorishiro-proxy

Thank you for your interest in contributing to yorishiro-proxy! This document
provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Commit Conventions](#commit-conventions)
- [Branch Strategy](#branch-strategy)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)
- [Dependency License Policy](#dependency-license-policy)
- [Developer Certificate of Origin (DCO)](#developer-certificate-of-origin-dco)
- [Security Issues](#security-issues)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code. Please report unacceptable
behavior as described in the Code of Conduct.

## Getting Started

yorishiro-proxy is an AI-agent-oriented network proxy that operates as an
MCP (Model Context Protocol) server. It provides traffic interception, recording,
and replay capabilities for security testing.

Before contributing, please familiarize yourself with:

- The [README](README.md) for an overview of the project
- The project architecture (TCP listener -> protocol detection -> protocol handler -> session recording -> MCP tools)
- The existing codebase under `internal/`

## Development Setup

### Prerequisites

- **Go 1.25+** (see `go.mod` for the exact version)
- **Node.js 24+** and **pnpm 9+** (for the web UI)
- **Make** (for build commands)
- **Git** (with support for `commit -s` for DCO sign-off)

### Building

```bash
# Clone the repository
git clone https://github.com/usk6666/yorishiro-proxy.git
cd yorishiro-proxy

# Build the binary (includes web UI build)
make build

# The binary is output to bin/yorishiro-proxy
```

### Testing

```bash
# Run all tests with race detection
make test

# Run tests with coverage report
make test-cover

# Run static analysis
make vet

# Run benchmarks
make bench
```

### Project Structure

```
cmd/yorishiro-proxy/       # Entry point
internal/
  mcp/                     # MCP server, tool definitions, handlers
  proxy/                   # TCP listener, protocol handler interface
  protocol/                # Protocol detection and handlers (HTTP/S, etc.)
  session/                 # Request/response recording, session management
  cert/                    # TLS certificate generation, CA management
  config/                  # Configuration loading
  logging/                 # Structured logging (log/slog)
web/                       # Web UI (dashboard)
```

## Coding Standards

This project follows Go standard style conventions:

- **Formatting**: Use `gofmt` / `goimports` for all Go code
- **Error handling**: Wrap errors with context using `fmt.Errorf("context: %w", err)`
- **Context propagation**: Pass `context.Context` as the first parameter
- **Package documentation**: Place package comments in `doc.go` or the first file in the package
- **Testing**: Write tests in `_test.go` files; use table-driven tests
- **Internal packages**: All packages under `internal/` are not exported; do not move them outside

### Additional Guidelines

- Keep functions focused and reasonably sized
- Use meaningful variable and function names
- Add comments for non-obvious logic
- Avoid introducing new external dependencies without checking the license policy (see below)

## Commit Conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type       | Description                                    |
|------------|------------------------------------------------|
| `feat`     | A new feature                                  |
| `fix`      | A bug fix                                      |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test`     | Adding or updating tests                       |
| `docs`     | Documentation changes                          |
| `ci`       | CI/CD configuration changes                    |
| `chore`    | Maintenance tasks                              |

### Examples

```
feat(proxy): add WebSocket protocol handler

fix(session): prevent duplicate session IDs on rapid requests

docs: update README with configuration examples

test(cert): add table-driven tests for certificate issuance
```

## Branch Strategy

- `main` -- always passes build and tests; protected branch
- Feature branches: `feat/<issue-id>-<short-desc>` (e.g., `feat/USK-12-http-handler`)
- Bug fix branches: `fix/<issue-id>-<short-desc>` (e.g., `fix/USK-45-session-leak`)
- Documentation branches: `docs/<issue-id>-<short-desc>`

All changes go through pull requests targeting `main`.

## Pull Request Process

1. **Create a feature branch** from `main` following the naming convention above
2. **Make your changes** with appropriate tests
3. **Ensure all checks pass** locally:
   ```bash
   make vet
   make test
   go build ./...
   ```
4. **Sign off your commits** with DCO (see [DCO section](#developer-certificate-of-origin-dco))
5. **Push your branch** and open a pull request against `main`
6. **Fill in the PR template** with a clear description of the changes
7. **Wait for CI** -- all checks must pass before review
8. **Address review feedback** -- make additional commits (do not force-push during review)
9. **Merge** -- a maintainer will merge the PR once approved

### PR Requirements

- All CI checks pass (`go vet`, `go test -race`, `go build`)
- Commits are signed off (DCO)
- Changes are covered by tests where applicable
- Documentation is updated if behavior changes

## Reporting Issues

We use GitHub Issues to track bugs and feature requests. Before opening a new
issue, please search existing issues to avoid duplicates.

### Bug Reports

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) and include:

- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Your environment (OS, Go version, yorishiro-proxy version)
- Relevant logs or error messages

### Feature Requests

Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md) and include:

- A clear description of the desired feature
- The motivation or use case
- Any ideas on implementation approach

## Dependency License Policy

yorishiro-proxy is licensed under Apache License 2.0. To maintain license
compatibility, we enforce strict rules on third-party dependencies.

### Allowed Licenses

- MIT
- BSD (2-clause, 3-clause)
- Apache-2.0
- ISC
- MPL-2.0

### Prohibited Licenses

- GPL-2.0, GPL-3.0
- LGPL-2.1, LGPL-3.0
- AGPL-3.0
- Any other copyleft license

**Before adding a new dependency**, verify its license falls within the allowed
list. Pull requests introducing dependencies with prohibited licenses will not
be accepted.

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin (DCO)](https://developercertificate.org/)
to ensure that contributors have the right to submit their contributions under
the project's license.

### What is DCO?

The DCO is a lightweight mechanism for contributors to certify that they wrote
or otherwise have the right to submit code to this project. By signing off on
your commits, you attest to the following:

> Developer Certificate of Origin Version 1.1
>
> Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
>
> Everyone is permitted to copy and distribute verbatim copies of this
> license document, but changing it is not allowed.
>
> Developer's Certificate of Origin 1.1
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I
>     have the right to submit it under the open source license
>     indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best
>     of my knowledge, is covered under an appropriate open source
>     license and I have the right under that license to submit that
>     work with modifications, whether created in whole or in part
>     by me, under the same open source license (unless I am
>     permitted to submit under a different license), as indicated
>     in the file; or
>
> (c) The contribution was provided directly to me by some other
>     person who certified (a), (b) or (c) and I have not modified
>     it.
>
> (d) I understand and agree that this project and the contribution
>     are public and that a record of the contribution (including all
>     personal information I submit with it, including my sign-off) is
>     maintained indefinitely and may be redistributed consistent with
>     this project or the open source license(s) involved.

### How to Sign Off

Add a `Signed-off-by` line to your commit messages. The easiest way is to use
the `-s` flag when committing:

```bash
git commit -s -m "feat(proxy): add WebSocket handler"
```

This produces a commit message like:

```
feat(proxy): add WebSocket handler

Signed-off-by: Your Name <your.email@example.com>
```

The name and email must match your Git configuration:

```bash
git config user.name "Your Name"
git config user.email "your.email@example.com"
```

### Signing Off Past Commits

If you forgot to sign off on a commit, you can amend it:

```bash
# Amend the most recent commit
git commit --amend -s --no-edit

# For multiple commits, use interactive rebase
git rebase -i HEAD~N  # where N is the number of commits
# Mark commits as "edit", then for each: git commit --amend -s --no-edit && git rebase --continue
```

### DCO Check

Pull requests are checked for proper DCO sign-off. If the check fails, please
sign off your commits as described above and push the updated commits.

## Security Issues

**Do not report security vulnerabilities through public GitHub issues.**

Please see our [Security Policy](SECURITY.md) for instructions on how to report
security vulnerabilities responsibly.

---

Thank you for contributing to yorishiro-proxy!
