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

Identify what to implement and how.

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

### 1-3. Select Issue

- If an Issue ID was given as argument, fetch it with `mcp__linear-server__get_issue`
- Otherwise, select the next available issue by:
  1. Priority (Urgent > High > Medium > Low)
  2. Dependency order (lower USK number first within same priority)

### 1-4. Determine File Actions

Cross-reference `envelope-implementation.md` §2 to determine which files should be:

- **Copied verbatim** (e.g., parser/ → layer/http1/parser/, TLS handshake code)
- **Written from scratch** (e.g., envelope/, layer/, pipeline steps)
- **Left untouched** (e.g., old code that coexists until N9)

### 1-5. Present Plan

Present the issue and implementation plan to the user. Include:

- Issue title, ID, description
- File actions (copy / scratch / untouched) with specific paths
- Dependencies on completed issues (with specific types/files they provide)
- Expected deliverables (new files, modified files, E2E tests)

Get confirmation before proceeding to Phase 2.

### 1-6. Update Linear Status

Update the issue status to **In Progress** with `mcp__linear-server__save_issue`.

---

## Phase 2: Implementation

### 2-1. Create Per-Issue Branch

Create a branch off `rewrite/rfc-001` for this issue:

```
rewrite/rfc-001/<issue-id>-<short-desc>
```

Example: `rewrite/rfc-001/USK-587-bytechunk-layer`

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

Execute the implementation based on the plan from Phase 1-5. Follow file actions:

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
   git push -u origin rewrite/rfc-001/<issue-id>-<short-desc>
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

   Resolves <Issue ID>
   Linear: https://linear.app/usk6666/issue/<Issue ID>

   🤖 Generated with [Claude Code](https://claude.com/claude-code)
   EOF
   )"
   ```

---

## Phase 4: Review & Close

### 4-1. Review Gate

Delegate to `/review-gate` for the created PR.

- For **N2** (vertical slice checkpoint) and **milestone-final issues**: review is **mandatory**
- For other issues: recommend review but proceed at user's discretion

### 4-2. Update Linear Status

Update the issue status to **In Review** with `mcp__linear-server__save_issue`.

Post a comment with the PR URL:
```
PR #<N> created: <PR URL>
Branch: rewrite/rfc-001/<issue-id>-<short-desc> → rewrite/rfc-001
```

### 4-3. Update Auto-Memory

Update `project_rfc001.md` to reflect:

- Which issues are now Done / In Review
- Current milestone progress (e.g., "N2: 3/5 issues complete")
- Any design decisions or friction resolutions discovered during implementation

### 4-4. Report Results

Present a summary:

```markdown
## RFC-001 Implementation Complete

| Field | Value |
|-------|-------|
| Issue | <Issue ID>: <title> |
| Branch | `rewrite/rfc-001/<issue-id>-<short-desc>` |
| PR | #<N> → `rewrite/rfc-001` |
| Tests | <N> passed |
| Status | In Review |

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
- Merge PRs sequentially into `rewrite/rfc-001` (resolve any conflicts on second merge)
- Both must pass verification gate (Phase 3-1) before PR creation

### Worktree Cleanup

After both agents complete and PRs are merged:

```bash
git worktree remove .claude/worktrees/agent-<agentId> --force 2>/dev/null || true
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
