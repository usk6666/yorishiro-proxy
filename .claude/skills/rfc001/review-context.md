# RFC-001 Review-Gate Context

This file holds the **product context** and **security context** blocks injected into the review-gate agent prompt during Phase 4 of the `/rfc001` skill. Loaded lazily — only read when the user opts into review (mandatory for N2 / milestone-final issues, recommended otherwise).

Replace `<X>` and `<milestone description>` placeholders before injecting.

## Product Context (verbatim)

```
yorishiro-proxy is a network proxy (MCP server) for AI agents.
Provides traffic interception, recording, and replay capabilities for vulnerability assessment.
Architecture: TCP Listener → Protocol Detection → Protocol Handler → Session Recording → MCP Tool

This PR is part of the RFC-001 rewrite (Envelope + Layered Connection Model).
Target branch: rewrite/rfc-001 (long-running rewrite branch, NOT main)
Milestone: N<X> — <milestone description>
```

## Security Context (verbatim)

```
yorishiro-proxy operates as a MITM proxy, therefore:
- It directly processes attacker-controlled traffic
- It holds the CA private key and dynamically issues certificates
- Session recordings may contain credentials (auth tokens, passwords)
- AI agents execute commands via MCP

RFC-001 data path packages (MITM triage targets):
- internal/envelope/, internal/layer/, internal/connector/, internal/channel/
- Plus existing: internal/protocol/, internal/proxy/, internal/flow/, internal/plugin/
```
