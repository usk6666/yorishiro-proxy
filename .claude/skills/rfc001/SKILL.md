---
description: "Enter RFC-001 rewrite mode. Load spec, implementation guide, and Linear state, then identify the next issue to implement on the rewrite/rfc-001 branch."
user-invokable: true
---

# /rfc001

Enter RFC-001 (Envelope + Layered Connection Model) implementation mode. This skill loads the context needed to implement N1-N9 issues on the `rewrite/rfc-001` branch, with token-efficient on-demand loading.

## Arguments

- `/rfc001` — Load context, list active milestones, propose next available issue
- `/rfc001 <Issue ID>` — Load context (short path) and start implementing the specified issue (e.g., `/rfc001 USK-587`)
- `/rfc001 <Milestone>` — Load context and run milestone planning if the milestone has 0 issues (e.g., `/rfc001 N9`)

---

## Phase 0: Context Load (token-efficient)

Load only the context relevant to the invocation. Avoid loading the whole spec or full Linear list unless required.

### 0-1. Branch Check

Verify current branch is `rewrite/rfc-001`. If not, `git checkout rewrite/rfc-001` (fetch first if needed). Pull the latest with `git pull --rebase origin rewrite/rfc-001`.

### 0-2. Always-Load Tier (small)

Read these files in full — they are foundational and small:

- `docs/rfc/envelope.md` **§1-2 (Motivation, Non-Goals)** and **§3.1-3.3 (Envelope, Message, Layer+Channel)** — the foundational types every milestone references
- `docs/rfc/envelope-implementation.md` **§1 (Strategy)** and **§2 (Milestone → spec section map AND file copy/scratch tables)** — the milestone-to-section mapping table is the lookup index for §0-3 below
- Auto-memory: `project_rfc001.md` (slim index) and `feedback_rfc001_impl.md`

### 0-3. On-Demand Tier (load only what the active milestone needs)

Determine the **active milestone** from the invocation:

- `/rfc001 <Issue ID>` → fetch the issue's milestone via `mcp__linear-server__get_issue`
- `/rfc001 <Milestone>` → use the argument
- `/rfc001` (no arg) → use the highest-priority IN PROGRESS milestone from the memory index

Then load **only** the per-milestone resources:

| Resource | Source |
|---|---|
| Spec sections | `envelope.md` sections from the §2 mapping table for that milestone |
| Implementation frictions | `envelope-implementation.md` §7 entries listed for that milestone (load only those Friction blocks, not the whole §7) |
| Per-milestone memory | `project_rfc001_<milestone>.md` (e.g., `project_rfc001_n8.md`); plus per-issue files like `project_rfc001_n8_usk669.md` if relevant |

If the milestone has **no detail file** (e.g., N1-N5 only have `project_rfc001_archive.md`), skip the per-milestone load — the index has enough public-surface info.

> **Escape hatch**: If during design review an unlisted spec section turns out to be load-bearing for the current issue, read it directly. Note the gap in PR description so the §2 mapping table can be corrected.

### 0-4. Do NOT load (unless explicitly needed)

- `envelope.md` §4 scenarios outside the milestone, §10 Alternatives (historical), Appendices
- `envelope-implementation.md` §3 (procedure), §6 (risks), §8 (rationale), §9-11 (background) — reference-only
- `project_rfc001_archive.md` — historical N1-N5
- Other milestones' `project_rfc001_<other>.md` files
- `.claude/agents/*.md` — load lazily at agent-launch time only

---

## Phase 1: Issue Selection & Analysis

Identify what to implement and how.

### 1-1. Linear State (token-efficient query)

Fetch only what's needed for the invocation:

| Invocation | Linear call(s) |
|---|---|
| `/rfc001 <Issue ID>` | Single `mcp__linear-server__get_issue(id)`. **Skip the list entirely.** |
| `/rfc001 <Milestone>` | `mcp__linear-server__list_issues({ project, projectMilestone, state IN (Backlog, Todo) })` for that milestone only |
| `/rfc001` (no arg) | `mcp__linear-server__list_issues({ project, projectMilestone: <active milestone from memory>, state IN (Backlog, Todo, In Progress) })`. Done milestones (N1-N7 per memory index) are NOT queried — the index is the source of truth for completed work. |

The memory index already reflects what's Done. Verify the selected issue's state with `get_issue` once before transitioning to In Progress.

### 1-2. Open Question Gate

Per memory index, OQ#1/OQ#2/OQ#3 are all RESOLVED as of 2026-04-29. If a future Open Question is added, gate here:

- **N6**: Open Question #1 — RFC §9.1 (RESOLVED)
- **N7**: Open Question #2 — RFC §9.2 (RESOLVED)
- **N8**: Open Question #3 — RFC §9.3 (RESOLVED)

If a milestone has an unresolved Open Question, **warn and stop** — do not proceed.

### 1-3. Select Issue — or Plan Milestone

- If an **Issue ID** was given as argument → already fetched in 1-1; proceed to **1-4**
- If a **milestone name** (e.g., `N9`) was given and the milestone has **0 issues** → go to **Phase 1-A**
- Otherwise, select the next available issue by priority/dependency order from 1-1's filtered list → proceed to **1-4**

### 1-4. Determine File Actions

Cross-reference `envelope-implementation.md` §2 to determine which files should be:

- **Copied verbatim** (e.g., parser/, TLS handshake code, cert/, macro/)
- **Written from scratch** (e.g., envelope/, layer/, pipeline steps)
- **Left untouched** (legacy code coexisting until N9)

### 1-5. Launch Design Review Agent

**Mandatory for every issue. Do not skip.**

1. Read `.claude/agents/design-reviewer.md` and `.claude/skills/rfc001/principles.md`
2. Build the prompt by replacing placeholders:

| Placeholder | Value |
|---|---|
| `{{SCOPE_DESCRIPTION}}` | Issue title + description + file actions from 1-4 |
| `{{SPEC_REFERENCES}}` | Sections selected by Phase 0-3 (e.g., `docs/rfc/envelope.md §3.5, §9.3`, `docs/rfc/envelope-implementation.md §7 Frictions 5-A, 5-B, 5-C`) |
| `{{PACKAGES_TO_SURVEY}}` | Packages the issue creates, modifies, or depends on |
| `{{COMPLETED_CONTEXT}}` | "Public surface exposed by completed milestones" section from `project_rfc001.md`, plus any per-milestone detail loaded in Phase 0-3 |
| `{{PRODUCT_IDENTITY}}` | `yorishiro-proxy is a MITM diagnostic proxy for AI agents. It intercepts, records, and replays network traffic for vulnerability assessment. Architecture: TCP Listener → Protocol Detection → Layer Stack → Pipeline → Session Recording → MCP Tool.` |
| `{{PRINCIPLES}}` | Body of `.claude/skills/rfc001/principles.md` (the seven RFC-001 principles) |

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

### 1-6. Present Plan

Present the issue and implementation plan to the user. Include:

- Issue title, ID, description
- File actions (copy / scratch / untouched) with specific paths
- Dependencies on completed issues (with specific types/files they provide — pull from public-surface table in memory index)
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

1. Read `.claude/agents/milestone-planner.md`, `.claude/agents/design-reviewer.md`, and `.claude/skills/rfc001/principles.md`
2. Build the prompt by replacing placeholders:

| Placeholder | Value |
|---|---|
| `{{MILESTONE_NAME}}` | Target milestone (e.g., "N9") |
| `{{MILESTONE_DESCRIPTION}}` | Full description from Linear milestone (`mcp__linear-server__get_milestone`) |
| `{{SPEC_REFERENCES}}` | Sections from §2 mapping table for this milestone, plus `docs/rfc/envelope-implementation.md §2` |
| `{{COMPLETED_CONTEXT}}` | "Public surface exposed by completed milestones" section from `project_rfc001.md` |
| `{{PRODUCT_IDENTITY}}` | Same as Phase 1-5 |
| `{{PRINCIPLES}}` | Body of `.claude/skills/rfc001/principles.md` |
| `{{DESIGN_REVIEW_AGENT}}` | Full Prompt Body from `.claude/agents/design-reviewer.md` |
| `{{CHECKLISTS}}` | From CLAUDE.md: "Config Checklist for New Feature Milestones" and/or "e2e Test Checklist for New Protocol Addition" — only if applicable |

3. Launch the agent:

```
Agent(
  description="Plan milestone <N>",
  subagent_type="general-purpose",
  prompt=<composed prompt>
)
```

### 1-A-2. Present Plan to User

Present the milestone planner's output: issue breakdown with dependency graph, resolved decisions, unresolved decisions for user to decide, recommended order. Get confirmation before creating issues.

### 1-A-3. Create Issues in Linear

After confirmation: create each issue via `mcp__linear-server__save_issue` under the target milestone with priority (Urgent/High/Medium/Low), scope, file list, dependencies, and acceptance criteria in the description.

### 1-A-4. Return to Issue Selection

Return to **Phase 1-3** to select the first issue by priority/dependency order. The selected issue then goes through Phase 1-4 → 1-5 → 1-6 → 1-7 as normal.

---

## Phase 2: Implementation

### 2-1. Create Per-Issue Branch

Create a branch off `rewrite/rfc-001`:

```
rfc001/<issue-id>-<short-desc>
```

Example: `rfc001/USK-587-bytechunk-layer`

### 2-2. Implementation Rules

**DO:**
- Read `docs/rfc/envelope.md` as the spec — every interface and type is defined there.
- Prioritize N2 vertical slice (USK-589: raw smuggling E2E) — already DONE; pattern still applies for any future vertical slice.
- Copy files listed as "copy verbatim" in `envelope-implementation.md` §2 (parser, TLS handshake, cert, macro, etc.) without modifying their logic.
- Write fresh code for everything else — do NOT evolve old code.
- Run `make build` frequently to catch compile errors early.
- Write at least 1 E2E test per milestone.

**DON'T:**
- **Never open** `internal/codec/`, `internal/pipeline/*_step.go`, `internal/protocol/`, `internal/proxy/`, or `internal/exchange/` for design inspiration. These are the HTTP-biased code being replaced. The only exception is files listed as "copy verbatim" in `envelope-implementation.md` §2.
- **Never add backwards-compatibility shims.** Compatibility is explicitly not needed.
- **Never normalize wire data.** Envelope.Raw is the source of truth. Message is a derived view.
- **Never start a milestone before its corresponding Open Question is resolved.** All current OQs are resolved; gate at Phase 1-2 if a future one is added.
- **Never defer E2E tests to "later".** Each milestone's E2E test is its success criterion.

### 2-3. Implement

Execute based on the plan from Phase 1-6. Follow file actions:

- **Copy verbatim**: copy the source file, adjust package/import paths only
- **Write from scratch**: implement from RFC spec, referencing the milestone's frictions in `envelope-implementation.md` §7 (loaded in Phase 0-3)

### 2-4. Write Tests

- Unit tests for new types and functions
- E2E test if this is the milestone's E2E issue (check `envelope-implementation.md` §4)
- Follow the e2e Test Subsystem Verification Checklist in `CLAUDE.md`

---

## Phase 3: Verify & PR

### 3-1. Verification Gate

```bash
gofmt -w .
make lint
make build
make test
```

If any step fails, fix and re-run. Do not skip.

### 3-2. Commit

Conventional Commits format:

```
<type>(<scope>): <description>

<body — what changed and why>

Refs: <Issue ID>
```

Scope reflects the new package (e.g., `envelope`, `layer`, `bytechunk`, `tlslayer`).

### 3-3. Push & Create PR

```bash
git push -u origin rfc001/<issue-id>-<short-desc>
gh pr create --base rewrite/rfc-001 \
  --title "<conventional commit title>" \
  --body "$(cat <<'EOF'
## Summary
- <bulleted list of changes>

## Test plan
- [ ] <test items>

## File Actions
- **Copied**: <list, or "None">
- **New**: <list>
- **Modified**: <list, or "None">

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

### 4-1. Determine Review Requirement (gate)

| Condition | Review |
|-----------|--------|
| **N2** (vertical slice checkpoint) | **Mandatory** |
| **Milestone-final issue** (last issue in N*X*) | **Mandatory** |
| Other issues | **Recommended** — ask the user; skip to Phase 5 if declined |

### 4-2 onwards: lazy-loaded

If review is required (or the user opts in), **Read `.claude/skills/rfc001/review-gate.md`** and follow it. It covers 4-2 (context build), 4-3 (agent launch + prompt template), 4-4 (verdict handling), 4-5 (worktree cleanup).

If the user declines review for a non-mandatory issue, skip directly to Phase 5 — do not Read `review-gate.md` or `review-context.md`.

---

## Phase 5: Close & Report

### 5-1. Update Linear Status

Update the issue status to **In Review** with `mcp__linear-server__save_issue`.

Post a comment with results:

| Event | Linear Comment |
|---|---|
| PR created, review passed | `"PR #N created → rewrite/rfc-001. Code Review APPROVED, Security Review APPROVED."` |
| PR created, review passed after fix | `"PR #N created → rewrite/rfc-001. All findings resolved after N fix round(s)."` |
| PR created, review escalated | `"PR #N created → rewrite/rfc-001. ESCALATION — N unresolved findings. Manual review needed."` |
| PR created, review skipped | `"PR #N created → rewrite/rfc-001. Review skipped (non-mandatory issue)."` |

### 5-2. Update Auto-Memory

Update **only the relevant per-milestone file** (e.g., `project_rfc001_n8.md` for N8 work). Update the slim **index file** `project_rfc001.md` only when:

- A milestone changes status (Done / In Progress / etc.)
- A new public type/package is exposed for downstream milestones
- An Open Question's status changes

Do NOT inline session-by-session blow-by-blow into `project_rfc001.md` — that's what per-milestone files are for.

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
|---|---|---|---|
| F-1 | HIGH | Correctness | FIXED (Round 1) |

### MITM-Rejected Findings (if any)
| ID | Source | Reason |
|---|---|---|
| F-2 | Code Review | Suggests header dedup — blocks smuggling testing |

### Milestone Progress
- N<X>: <done>/<total> issues complete
- Next: <next issue ID and title>
```

---

## Parallel Execution

The RFC allows certain milestones to run in parallel (historically: N4 ∥ N5; future milestones may add similar opportunities). When two issues from compatible milestones are both ready and the user requests parallel execution:

### Launch

Launch up to 2 sub-agents with worktree isolation, each receiving:
- Full RFC-001 context (Phase 0-3 outputs filtered for that milestone)
- File action list for its issue
- Instructions to create per-issue branch off `rewrite/rfc-001` and create PR

### Constraints

- Maximum **2** concurrent sub-agents
- Each sub-agent must target different packages
- Both must pass verification gate (Phase 3-1) before PR creation
- All PRs must target `rewrite/rfc-001` as base branch

### Review Gate for Parallel PRs

Launch review gates for both PRs as **background** agents (same pattern as `/orchestrate` Phase 2.5). Build prompts following Phase 4-2 and 4-3. Merge PRs sequentially into `rewrite/rfc-001` only after review passes (resolve any conflicts on second merge).

### Worktree Cleanup

After both agents complete, reviews pass, and PRs are merged, collect **all** agent IDs (implementation + review-gate + sub-agents reported in `agent_ids`):

```bash
git worktree remove .claude/worktrees/agent-<agentId> --force 2>/dev/null || true
git worktree prune
```

Only target worktrees of sub-agents launched in this session.

---

## Notes

- This skill is the **single entry point** for all RFC-001 rewrite work. Always invoke it before starting any N1-N9 implementation.
- **Do NOT delegate to `/implement`** — its feature-branch model (`feat/USK-XX-xxx` off `main`) is incompatible with the `rewrite/rfc-001` branch strategy.
- Per-issue branches off `rewrite/rfc-001` enable code review per issue while keeping the long-running branch as the integration target.
- If you encounter a design question not covered by the RFC, do NOT improvise. Flag it to the user and suggest updating the RFC (it can go back to draft status).
- The 12 pseudo-code frictions in `envelope-implementation.md` §7 cover most foreseeable snags. The Phase 0-3 mapping table tells you which ones to load for the active milestone.
- `CLAUDE.md` still references M36-M44 in some places. Ignore those — they are superseded by RFC-001 and will be cleaned up in N9.
