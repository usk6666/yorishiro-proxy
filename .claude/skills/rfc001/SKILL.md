---
description: "Enter RFC-001 rewrite mode. Load spec, implementation guide, and Linear state, then identify the next issue to implement on the rewrite/rfc-001 branch."
user-invokable: true
---

# /rfc001

Enter RFC-001 (Envelope + Layered Connection Model) implementation mode. This skill loads the full context needed to implement N1-N9 issues on the `rewrite/rfc-001` branch.

## Arguments

- `/rfc001` — Load context and show next available issue
- `/rfc001 <Issue ID>` — Load context and start implementing the specified issue (e.g., `/rfc001 USK-587`)

---

## Phase 0: Context Load

Load all context needed before any implementation decisions.

### 0-1. Branch Check

Verify current branch is `rewrite/rfc-001`. If not, `git checkout rewrite/rfc-001` (fetch first if needed). Pull the latest with `git pull --rebase origin rewrite/rfc-001`.

### 0-2. Load Specification Documents

Read the following documents **in full**:

- `docs/rfc/envelope.md` — the RFC itself (authoritative spec)
- `docs/rfc/envelope-implementation.md` — implementation strategy, file copy table, pseudo-code frictions, don't-do list

### 0-3. Load Auto-Memory

Read `project_rfc001.md` and `feedback_rfc001_impl.md` from auto-memory to confirm current state and implementation discipline rules.

---

## Phase 1: Issue Selection & Analysis

Identify what to implement and how. Delegates design analysis to reusable agents.

### 1-1. Check Linear State

List issues in the `yorishiro-proxy` project for the current N milestones (N1 through N9). Identify:

- Which issues are **Done**
- Which issues are **In Progress**
- Which issues are **available** (Backlog/Todo, dependencies satisfied)

### 1-2. Open Question Gate

If the target issue belongs to a milestone with a blocking Open Question, **warn and stop**:

- **N6**: Open Question #1 (HTTP/2 flow control) — RFC §9.1
- **N7**: Open Question #2 (gRPC envelope granularity) — RFC §9.2
- **N8**: Open Question #3 (Starlark plugin API shape) — RFC §9.3

Do not proceed. Flag to the user and suggest resolving the Open Question first.

### 1-3. Select Issue — or Plan Milestone

- If an **Issue ID** was given as argument, fetch it with `mcp__linear-server__get_issue` → proceed to **1-4**
- If a **milestone name** (e.g., `N3`) was given and the milestone has **0 issues** → go to **Phase 1-A**
- Otherwise, select the next available issue by priority/dependency order → proceed to **1-4**

### 1-4. Determine File Actions

Cross-reference `envelope-implementation.md` §2 to determine which files should be:

- **Copied verbatim** (e.g., parser/ → layer/http1/parser/, TLS handshake code)
- **Written from scratch** (e.g., envelope/, layer/, pipeline steps)
- **Left untouched** (e.g., old code that coexists until N9)

### 1-5. Launch Design Review Agent

**Mandatory for every issue. Do not skip.**

1. Read `.claude/agents/design-reviewer.md`
2. Build the prompt by replacing placeholders:

| Placeholder | Value |
|-------------|-------|
| `{{SCOPE_DESCRIPTION}}` | Issue title + description + file actions from 1-4 |
| `{{SPEC_REFERENCES}}` | `docs/rfc/envelope.md` (relevant §), `docs/rfc/envelope-implementation.md` §2 and §7 |
| `{{PACKAGES_TO_SURVEY}}` | Packages the issue creates, modifies, or depends on |
| `{{COMPLETED_CONTEXT}}` | From auto-memory `project_rfc001.md` — completed milestones, new packages, key decisions |
| `{{PRODUCT_IDENTITY}}` | `yorishiro-proxy is a MITM diagnostic proxy for AI agents. It intercepts, records, and replays network traffic for vulnerability assessment. Architecture: TCP Listener → Protocol Detection → Layer Stack → Pipeline → Session Recording → MCP Tool.` |
| `{{PRINCIPLES}}` | See **Principles Block** below |

3. Launch the agent:

```
Agent(
  description="Design review: <Issue ID>",
  subagent_type="general-purpose",
  prompt=<composed prompt>
)
```

4. Process the result:
   - **All resolved** → incorporate decisions into the plan, proceed to 1-6
   - **Unresolved items exist** → present ONLY unresolved items to the user for decision. Do NOT present resolved items as questions.

#### Principles Block

Used for `{{PRINCIPLES}}` in design-reviewer and milestone-planner agents:

```
1. Wire fidelity: Envelope.Raw must contain the exact wire-observed bytes. Never reconstruct wire bytes from structured fields. Unmodified data must take the zero-copy fast path (write Raw directly).
2. No normalization: Header case, order, duplicates, and whitespace must be preserved as observed on the wire. Do not merge, canonicalize, or reorder.
3. L7/L4 duality: Every protocol must provide both a structured Message view AND raw bytes (Envelope.Raw). L7 parsing is an overlay, not a replacement.
4. Protocol confinement: HTTP-specific fields belong on HTTPMessage, not Envelope. Pipeline Steps dispatch via type-switch on env.Message, not if-else on Protocol string.
5. Scrap-and-build: No backwards compatibility needed. No shims, no old-code evolution. Write fresh from the RFC spec.
6. net/http ban: Data path code must not use net/http types. Use internal types (parser.RawRequest/RawResponse, hpack types). net/http is permitted only in control plane (MCP server, CLI).
7. Attacker-controlled input: The parser handles malformed input gracefully (Anomaly, not panic). Buffer limits are enforced.
```

### 1-6. Present Plan

Present the issue and implementation plan to the user. Include:

- Issue title, ID, description
- File actions (copy / scratch / untouched) with specific paths
- Dependencies on completed issues (with specific types/files they provide)
- Expected deliverables (new files, modified files, E2E tests)
- **Key design decisions** resolved by the design review (summary table)
- **Deferred items** (what is explicitly out of scope and why)

Get confirmation before proceeding to Phase 2.

### 1-7. Update Linear Status

Update the issue status to **In Progress** with `mcp__linear-server__save_issue`.

---

## Phase 1-A: Milestone Planning

**Triggered when:** Phase 1-3 finds the target milestone has 0 issues.

### 1-A-1. Launch Milestone Planner Agent

1. Read `.claude/agents/milestone-planner.md`
2. Read `.claude/agents/design-reviewer.md` — inject its **full Prompt Body** into the `{{DESIGN_REVIEW_AGENT}}` placeholder
3. Build the prompt by replacing placeholders:

| Placeholder | Value |
|-------------|-------|
| `{{MILESTONE_NAME}}` | Target milestone (e.g., "N3") |
| `{{MILESTONE_DESCRIPTION}}` | Full description from Linear milestone |
| `{{SPEC_REFERENCES}}` | `docs/rfc/envelope.md`, `docs/rfc/envelope-implementation.md` |
| `{{COMPLETED_CONTEXT}}` | From auto-memory `project_rfc001.md` |
| `{{PRODUCT_IDENTITY}}` | Same as Phase 1-5 |
| `{{PRINCIPLES}}` | Same **Principles Block** as Phase 1-5 |
| `{{DESIGN_REVIEW_AGENT}}` | Full Prompt Body from `design-reviewer.md` |
| `{{CHECKLISTS}}` | From CLAUDE.md: "Config Checklist for New Feature Milestones" and "e2e Test Checklist for New Protocol Addition" (include only if applicable to this milestone) |

4. Launch the agent:

```
Agent(
  description="Plan milestone <N>",
  subagent_type="general-purpose",
  prompt=<composed prompt>
)
```

### 1-A-2. Present Plan to User

Present the milestone planner's output:

- Issue breakdown with dependency graph
- Resolved design decisions (summary)
- Unresolved decisions (if any) — ask the user to decide
- Recommended implementation order

Get confirmation before creating issues.

### 1-A-3. Create Issues in Linear

After user confirmation:

1. Create each issue via `mcp__linear-server__save_issue` under the target milestone
2. Set priority: Urgent/High for blockers, Medium for parallelizable, Low for docs/cleanup
3. Include scope, file list, dependencies, and acceptance criteria in each issue description

### 1-A-4. Return to Issue Selection

Return to **Phase 1-3** to select the first issue by priority/dependency order. The selected issue then goes through Phase 1-4 → 1-5 → 1-6 → 1-7 as normal.

---

## Phase 2: Implementation

### 2-1. Create Per-Issue Branch

Create a branch off `rewrite/rfc-001` for this issue:

```
rfc001/<issue-id>-<short-desc>
```

Example: `rfc001/USK-587-bytechunk-layer`

### 2-2. Implementation Rules

Before writing code, internalize these rules:

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

### 2-3. Implement

Execute the implementation based on the plan from Phase 1-6. Follow file actions:

- **Copy verbatim**: Copy the source file, adjust package/import paths only
- **Write from scratch**: Implement from the RFC spec, referencing pseudo-code frictions in `envelope-implementation.md` §7

### 2-4. Write Tests

Write tests for the implementation:

- Unit tests for new types and functions
- E2E test if this is the milestone's E2E issue (check `envelope-implementation.md` §4)
- Follow the e2e Test Subsystem Verification Checklist in `CLAUDE.md`

---

## Phase 3: Verify & PR

### 3-1. Verification Gate

Run the full verification suite. **All must pass** before proceeding:

```bash
gofmt -w .
make lint      # gofmt check + go vet + staticcheck + ineffassign
make build
make test
```

If any step fails, fix the issue and re-run. Do not skip.

### 3-2. Commit

Commit in Conventional Commits format:

```
<type>(<scope>): <description>

<body — what changed and why>

Refs: <Issue ID>
```

- Include `Refs: <Issue ID>` in the footer
- Scope should reflect the new package (e.g., `envelope`, `layer`, `bytechunk`, `tlslayer`)

### 3-3. Push & Create PR

1. Push the per-issue branch:
   ```bash
   git push -u origin rfc001/<issue-id>-<short-desc>
   ```

2. Create PR targeting `rewrite/rfc-001`:
   ```bash
   gh pr create --base rewrite/rfc-001 \
     --title "<conventional commit title>" \
     --body "$(cat <<'EOF'
   ## Summary
   - <bulleted list of changes>

   ## Test plan
   - [ ] <test items>

   ## File Actions
   - **Copied**: <list of files copied verbatim, or "None">
   - **New**: <list of new files>
   - **Modified**: <list of modified existing files, or "None">

   ## Design Decisions
   <key decisions from design review, with citations>

   Resolves <Issue ID>
   Linear: https://linear.app/usk6666/issue/<Issue ID>

   🤖 Generated with [Claude Code](https://claude.com/claude-code)
   EOF
   )"
   ```

---

## Phase 4: Review Gate

Run the `/review-gate` flow for the created PR.

### 4-1. Determine Review Requirement

| Condition | Review |
|-----------|--------|
| **N2** (vertical slice checkpoint) | **Mandatory** |
| **Milestone-final issue** (last issue in N*X*) | **Mandatory** |
| Other issues | **Recommended** — ask the user; skip to Phase 5 if declined |

### 4-2. Build Review Context

1. Read agent templates with the Read tool:
   - `.claude/agents/code-reviewer.md`
   - `.claude/agents/security-reviewer.md`
   - `.claude/agents/fixer.md`

2. Build **product context**:
   ```
   yorishiro-proxy is a network proxy (MCP server) for AI agents.
   Provides traffic interception, recording, and replay capabilities for vulnerability assessment.
   Architecture: TCP Listener → Protocol Detection → Protocol Handler → Session Recording → MCP Tool

   This PR is part of the RFC-001 rewrite (Envelope + Layered Connection Model).
   Target branch: rewrite/rfc-001 (long-running rewrite branch, NOT main)
   Milestone: N<X> — <milestone description>
   ```

3. Build **security context**:
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

### 4-3. Launch Review Gate Agent

Read `.claude/skills/review-gate/SKILL.md` at invocation time and include its **full content**
in the sub-agent prompt. This ensures the review-gate flow is always the latest version.

Launch a single Agent that executes the entire review → fix → re-review cycle:

```
Agent(
  description="Review gate PR #<N> (RFC-001)",
  subagent_type="general-purpose",
  isolation="worktree",
  prompt=<review gate prompt>
)
```

The prompt must include:
- The full content of `/review-gate` SKILL.md
- PR number, head branch (`rfc001/<issue-id>-<short-desc>`), base branch (`rewrite/rfc-001`)
- Issue ID
- Product context and security context (from 4-2)
- Content of all three agent templates (code-reviewer, security-reviewer, fixer)

> **Single Source of Truth**: Do not duplicate the review-gate flow steps in this skill.
> Always read the SKILL.md at prompt construction time.

**Expected output format** from the review gate agent:

```
REVIEW_GATE_RESULT:
  pr_number: <N>
  code_review: APPROVED | CHANGES_REQUESTED
  security_review: APPROVED | CHANGES_REQUESTED
  final_verdict: APPROVED | ESCALATED
  fix_rounds: 0 | 1 | 2
  unresolved_findings: [...]
  agent_ids: [<all sub-agent IDs launched>]
```

### 4-4. Handle Verdict

| Verdict | Action |
|---------|--------|
| **APPROVED** | Proceed to Phase 5. Record `fix_rounds` for the report. |
| **ESCALATED** | Report unresolved findings to the user. **Do not merge.** Ask whether to proceed to Phase 5 (with issue noted) or stop entirely. |

### 4-5. Worktree Cleanup

Collect all agent IDs returned by the review gate agent (its own ID + `agent_ids` from its output).
Delete **only those worktrees**:

```bash
git worktree remove .claude/worktrees/agent-<agentId> --force 2>/dev/null || true
```

After all deletions:

```bash
git worktree prune
```

---

## Phase 5: Close & Report

### 5-1. Update Linear Status

Update the issue status to **In Review** with `mcp__linear-server__save_issue`.

Post a comment with review results:

| Event | Linear Comment |
|-------|---------------|
| PR created, review passed | `"PR #N created → rewrite/rfc-001. Code Review APPROVED, Security Review APPROVED."` |
| PR created, review passed after fix | `"PR #N created → rewrite/rfc-001. All findings resolved after N fix round(s)."` |
| PR created, review escalated | `"PR #N created → rewrite/rfc-001. ESCALATION — N unresolved findings. Manual review needed."` |
| PR created, review skipped | `"PR #N created → rewrite/rfc-001. Review skipped (non-mandatory issue)."` |

### 5-2. Update Auto-Memory

Update `project_rfc001.md` to reflect:

- Which issues are now Done / In Review
- Current milestone progress (e.g., "N2: 3/5 issues complete")
- Any design decisions or friction resolutions discovered during implementation

### 5-3. Report Results

Present a summary:

```markdown
## RFC-001 Implementation Complete

| Field | Value |
|-------|-------|
| Issue | <Issue ID>: <title> |
| Branch | `rfc001/<issue-id>-<short-desc>` |
| PR | #<N> → `rewrite/rfc-001` |
| Tests | <N> passed |
| Review | APPROVED / ESCALATED / Skipped |
| Fix Rounds | 0 / 1 / 2 |
| Status | In Review |

### Review Findings (if any)
| ID | Severity | Category | Status |
|----|----------|----------|--------|
| F-1 | HIGH | Correctness | FIXED (Round 1) |

### MITM-Rejected Findings (if any)
| ID | Source | Reason |
|----|--------|--------|
| F-2 | Code Review | Suggests header dedup — blocks smuggling testing |

### Milestone Progress
- N<X>: <done>/<total> issues complete
- Next: <next issue ID and title>
```

---

## Parallel Execution (N4 ∥ N5)

The RFC allows N4 (Connector Completion) and N5 (Job + Macro Integration) to run in parallel.
When both milestones are ready and the user requests parallel execution:

### Launch

Launch two sub-agents with worktree isolation:

```
Agent(
  description="RFC-001: Implement <Issue ID> (N4)",
  subagent_type="general-purpose",
  isolation="worktree",
  prompt=<rfc001-implementer prompt for N4 issue>
)
Agent(
  description="RFC-001: Implement <Issue ID> (N5)",
  subagent_type="general-purpose",
  isolation="worktree",
  prompt=<rfc001-implementer prompt for N5 issue>
)
```

Each sub-agent receives:
- Full RFC-001 context (spec + implementation guide + implementation rules from Phase 2-2)
- File action list for its issue
- Instructions to create per-issue branch off `rewrite/rfc-001` and create PR

### Constraints

- Maximum **2** concurrent sub-agents for N4 ∥ N5
- Each sub-agent must target different packages (N4 = connector/, N5 = job/macro)
- Both must pass verification gate (Phase 3-1) before PR creation
- All PRs must target `rewrite/rfc-001` as base branch

### Review Gate for Parallel PRs

After both implementation agents complete and PRs are created, launch review gates
for both PRs as **background** agents (same pattern as `/orchestrate` Phase 2.5):

```
Agent(
  description="Review gate PR #<N1> (N4)",
  subagent_type="general-purpose",
  isolation="worktree",
  run_in_background=true,
  prompt=<review gate prompt for N4 PR>
)
Agent(
  description="Review gate PR #<N2> (N5)",
  subagent_type="general-purpose",
  isolation="worktree",
  run_in_background=true,
  prompt=<review gate prompt for N5 PR>
)
```

Build the prompt following the same procedure as Phase 4-2 and 4-3.
Merge PRs sequentially into `rewrite/rfc-001` only after review passes (resolve any conflicts on second merge).

### Worktree Cleanup

After both agents complete, reviews pass, and PRs are merged, collect **all** agent IDs
(implementation agents + review gate agents + sub-agents reported in `agent_ids`):

```bash
git worktree remove .claude/worktrees/agent-<agentId> --force 2>/dev/null || true
```

After all deletions:

```bash
git worktree prune
```

Only target worktrees of sub-agents launched in this session.

---

## Notes

- This skill is the **single entry point** for all RFC-001 rewrite work. Always invoke it before starting any N1-N9 implementation.
- **Do NOT delegate to `/implement`** — its feature-branch model (`feat/USK-XX-xxx` off `main`) is incompatible with the `rewrite/rfc-001` branch strategy. This skill contains its own complete workflow.
- Per-issue branches off `rewrite/rfc-001` enable code review per issue while keeping the long-running branch as the integration target.
- If you encounter a design question not covered by the RFC, do NOT improvise. Flag it to the user and suggest updating the RFC (it can go back to draft status).
- The 12 pseudo-code frictions documented in `envelope-implementation.md` §7 cover most foreseeable implementation snags. Check there before asking.
- `CLAUDE.md` still references M36-M44 in some places. Ignore those references — they are superseded by RFC-001 and will be cleaned up in N9.
