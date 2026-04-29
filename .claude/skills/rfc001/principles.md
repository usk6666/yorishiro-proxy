# RFC-001 Principles

This file is the canonical source for the `{{PRINCIPLES}}` placeholder used by the design-reviewer and milestone-planner agents. The `/rfc001` skill reads it at agent-launch time and injects the body into the agent prompt. Keeping it as a sidecar file avoids inlining the same block into both SKILL.md branches (Phase 1-5 and Phase 1-A) and into Phase 4 review prompts.

## Principles Block (verbatim — inject as `{{PRINCIPLES}}`)

```
1. Wire fidelity: Envelope.Raw must contain the exact wire-observed bytes. Never reconstruct wire bytes from structured fields. Unmodified data must take the zero-copy fast path (write Raw directly).
2. No normalization: Header case, order, duplicates, and whitespace must be preserved as observed on the wire. Do not merge, canonicalize, or reorder.
3. L7/L4 duality: Every protocol must provide both a structured Message view AND raw bytes (Envelope.Raw). L7 parsing is an overlay, not a replacement.
4. Protocol confinement: HTTP-specific fields belong on HTTPMessage, not Envelope. Pipeline Steps dispatch via type-switch on env.Message, not if-else on Protocol string.
5. Scrap-and-build: No backwards compatibility needed. No shims, no old-code evolution. Write fresh from the RFC spec.
6. net/http ban: Data path code must not use net/http types. Use internal types (parser.RawRequest/RawResponse, hpack types). net/http is permitted only in control plane (MCP server, CLI).
7. Attacker-controlled input: The parser handles malformed input gracefully (Anomaly, not panic). Buffer limits are enforced.
```
