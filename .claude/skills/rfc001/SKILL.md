---
description: "Enter RFC-001 rewrite mode. Load spec, implementation guide, and Linear state, then identify the next issue to implement on the rewrite/rfc-001 branch."
user-invokable: true
---

# /rfc001

Enter RFC-001 (Envelope + Layered Connection Model) implementation mode. This skill loads the full context needed to implement N1-N9 issues on the `rewrite/rfc-001` branch.

## Arguments

- `/rfc001` — Load context and show next available issue
- `/rfc001 <Issue ID>` — Load context and start implementing the specified issue (e.g., `/rfc001 USK-581`)

## Steps

1. **Branch check**: Verify current branch is `rewrite/rfc-001`. If not, `git checkout rewrite/rfc-001` (fetch first if needed).

2. **Load spec**: Read the following documents in full:
   - `docs/rfc/envelope.md` — the RFC itself (authoritative spec)
   - `docs/rfc/envelope-implementation.md` — implementation strategy, file copy table, pseudo-code frictions, don't-do list, session notes

3. **Load memory**: Read `project_rfc001.md` and `feedback_rfc001_impl.md` from auto-memory to confirm current state and rules.

4. **Check Linear state**: List issues in the `yorishiro-proxy` project for the current N milestone (N1 through N9). Identify:
   - Which issues are Done
   - Which issues are In Progress
   - Which issues are available (Backlog/Todo, dependencies satisfied)

5. **Open Question gate**: If the target issue belongs to a milestone with a blocking Open Question, warn and stop:
   - N6: Open Question #1 (HTTP/2 flow control) — RFC §9.1
   - N7: Open Question #2 (gRPC envelope granularity) — RFC §9.2
   - N8: Open Question #3 (Starlark plugin API shape) — RFC §9.3

6. **Present the issue**: If an Issue ID was given as argument, fetch it. Otherwise, select the next available issue by priority (Urgent > High > Medium > Low) with dependency order (lower USK number first within same priority).

7. **Present implementation rules**: Before starting any implementation, display the following reminders:

   ### Implementation Rules (from RFC-001)

   **DO:**
   - Read `docs/rfc/envelope.md` as the spec. Every interface and type is defined there.
   - Prioritize N2 vertical slice (USK-589: raw smuggling E2E) above all else — this is the design validation checkpoint.
   - Copy files listed as "copy verbatim" in `envelope-implementation.md` §2 (parser, TLS handshake, cert, macro, etc.) without modifying their logic.
   - Write fresh code for everything else — do NOT evolve old code.
   - Run `make build` frequently to catch compile errors early.
   - Write at least 1 E2E test per milestone.

   **DON'T:**
   - **Never open** `internal/codec/`, `internal/pipeline/*_step.go`, `internal/protocol/`, `internal/proxy/`, or `internal/exchange/` for design inspiration. These are the HTTP-biased code being replaced. The only exception is files listed as "copy verbatim" in `envelope-implementation.md` §2.
   - **Never add backwards-compatibility shims.** Compatibility is explicitly not needed.
   - **Never normalize wire data.** Envelope.Raw is the source of truth. Message is a derived view.
   - **Never start N6/N7/N8 without resolving the corresponding Open Question first.**
   - **Never defer E2E tests to "later".** Each milestone's E2E test is its success criterion.

8. **Determine file actions**: For the selected issue, cross-reference `envelope-implementation.md` §2 to determine which files should be:
   - **Copied verbatim** (e.g., parser/ → layer/http1/parser/, TLS handshake code)
   - **Written from scratch** (e.g., envelope/, layer/, pipeline steps)
   - **Left untouched** (e.g., old code that coexists until N9)

9. **Proceed**: Either:
   - Start implementing (if the user confirms)
   - Delegate to `/implement <Issue ID>` (which handles branch/commit/PR workflow)
   - Show a plan and ask for confirmation

## Notes

- This skill is the **single entry point** for all RFC-001 rewrite work. Always invoke it before starting any N1-N9 implementation.
- The `rewrite/rfc-001` branch is long-running. All N1-N9 work happens there. Do NOT create separate feature branches for individual issues — commit directly to `rewrite/rfc-001`.
- If you encounter a design question not covered by the RFC, do NOT improvise. Flag it to the user and suggest updating the RFC (it can go back to draft status).
- The 12 pseudo-code frictions documented in `envelope-implementation.md` §7 cover most foreseeable implementation snags. Check there before asking.
- `CLAUDE.md` still references M36-M44 in some places. Ignore those references — they are superseded by RFC-001 and will be cleaned up in N9.
