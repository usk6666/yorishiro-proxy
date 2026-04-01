---
description: "Orchestrator for parallel Linear Issue implementation. Analyze milestones and dependencies, then delegate implementation to sub-agents in optimal order and concurrency"
user-invokable: true
---

# /orchestrate

An orchestration skill that understands milestones, analyzes dependencies, and delegates implementation of multiple Linear Issues to sub-agents.

## Arguments

- `/orchestrate` — Analyze active milestones and suggest the next Issues to implement
- `/orchestrate <Issue ID> [Issue ID...]` — Implement specified Issues considering dependencies
- `/orchestrate milestone <name>` — Implement Issues in the specified milestone in dependency order
- `/orchestrate status` — Show all milestone progress + running sub-agent status

---

## Steps

### Phase 0: Product Understanding — Milestone and Current State Overview

**Do this first on every run.** The orchestrator first adopts the product owner's perspective.

#### 0-1. Fetch All External Context (Parallel)

Launch all of the following **in a single parallel batch** (5 calls total):

- `mcp__linear-server__list_milestones(project=yorishiro-proxy)`
- `mcp__linear-server__get_document(id=d413edd7-d296-433a-ab94-11d4dd57d883)` (roadmap)
- `mcp__linear-server__list_issues(team=Usk6666, project=yorishiro-proxy, state=started)`
- `mcp__linear-server__list_issues(team=Usk6666, project=yorishiro-proxy, state=backlog)`
- `mcp__linear-server__list_issues(team=Usk6666, project=yorishiro-proxy, state=unstarted)`

#### 0-2. Process Fetched Data

From the milestone list, classify progress:

- `progress == 100` → Complete
- `0 < progress < 100` → Active (in progress)
- `progress == 0` → Not started

From the roadmap document, extract:

- **Product goal**: What is being built and for whom
- **Milestone structure**: The goal and delivered value of each milestone
- **Inter-milestone dependencies**: Which milestone depends on which
- **Issue ordering within milestones**: Natural implementation order of Issues within each milestone
- **Technical decisions**: Design decisions already made (storage choice, protocol strategy, etc.)

Group fetched Issues by `projectMilestone` field.
**Do not fetch completed Issues.** Use milestone progress + roadmap Issue table to track completion status.
Only fetch specific completed Issues individually with `get_issue(id)` when needed for building dependency context.

> **Note**: Codebase state checks (file existence, type verification) are deferred to Phase 1-1
> where they can be done precisely for the specific dependencies that matter.

#### 0-3. Generate Current State Summary

Present a concise milestone-based summary to the user:

```markdown
## Project State Analysis

### Milestone Progress
| Milestone | Progress | Remaining |
|-----------|----------|-----------|
| M1: Foundation | 100% | — |
| M2: MCP Interface v2 | 79% | 3 issues |  ← ACTIVE
| M3: Active Testing | 0% | N issues |
| M4: Multi-Protocol | 0% | N issues |
| M5: Production Ready | 0% | N issues |

### Active: M2 — MCP Interface v2
| ID | Title | Status | Priority |
|----|-------|--------|----------|
| USK-79 | ... | Backlog | High |
| ...
```

---

### Phase 1: Dependency Analysis and Execution Plan

#### 1-1. Build Dependency Graph Between Issues

Analyze the following dependencies from milestone structure and Issue descriptions:

**Inter-milestone dependencies** (dynamic analysis based on roadmap):
- Read dependency information from the milestone sections of the roadmap document
- Determine dependency satisfaction from milestone progress (`progress == 100` → satisfied)
- Do not start Issues in a milestone whose prerequisite milestone is not complete

**Intra-milestone dependencies** (inferred from Issue content):
Fetch each Issue's description with `mcp__linear-server__get_issue` and determine dependencies from these perspectives:

1. **Data dependency**: Issue A creates types/interfaces that Issue B uses
2. **Functional dependency**: Issue A's functionality must work before Issue B can be tested
3. **Integration dependency**: There is an Issue C that combines the outputs of Issues A and B

Also refer to Linear's `blockedBy` / `blocks` fields, but if not set,
infer dependency relationships from the roadmap's Issue ordering and Issue content.

When a dependency is identified, **verify it against the actual codebase** (e.g., check that
the expected file/type/interface exists with Glob or Grep). This replaces the former Phase 0
codebase check with targeted, dependency-driven verification.

#### 1-2. Identify Parallel Execution Groups

Derive groups of Issues (parallel execution batches) that can be run simultaneously from the dependency graph.

**Conditions for parallel execution:**
- No mutual dependencies
- Primarily modify different packages/files (low conflict risk)
- Issues from the same milestone or from milestones whose dependencies are satisfied

#### 1-3. Present Execution Plan

Present the plan to the user in the following format and get approval:

```markdown
## Execution Plan

### Target Milestone: M2 — MCP Interface v2

### Batch 1 (Parallel Execution)
| Issue | Title | Branch | Reason |
|-------|-------|--------|--------|
| USK-XX | ... | feat/USK-XX-xxx | No dependencies |
| USK-YY | ... | feat/USK-YY-yyy | No dependencies |

### Batch 2 (After Batch 1, Parallel Execution)
| Issue | Title | Branch | Dependencies |
|-------|-------|--------|-------------|
| USK-AA | ... | feat/USK-AA-aaa | USK-XX |

### Concurrency: Max 2 (Batch 1) → Sequential (Batch 2)
### Estimated PRs: 3
```

---

### Phase 2: Sub-Agent Launch and Management

#### 2-1. Per-Batch Execution

Based on the plan, launch sub-agents per batch.
**Launch Issues within a batch in parallel; execute between batches sequentially.**

Task tool settings for each Issue:

- `subagent_type`: `"general-purpose"`
- `isolation`: `"worktree"` — Each sub-agent works in an independent git worktree
- `description`: Short description including the Issue ID (e.g., `"Implement USK-30"`)
- `prompt`: Read the `.claude/agents/implementer.md` prompt template, replace placeholders with actual values, and pass it

**Placeholder list:**
- `{{ISSUE_ID}}` → Issue ID (e.g., `USK-30`)
- `{{ISSUE_TITLE}}` → Issue title
- `{{ISSUE_DESCRIPTION}}` → Issue description (Markdown)
- `{{ISSUE_LABELS}}` → Comma-separated label names
- `{{BRANCH_NAME}}` → Branch name (e.g., `feat/USK-30-http-handler`)
- `{{BRANCH_TYPE}}` → `feat` / `fix` / `chore`
- `{{PRODUCT_CONTEXT}}` → Product context built in Phase 0 (described below)
- `{{DEPENDENCY_CONTEXT}}` → Dependency context for this Issue (described below)

**Building `{{PRODUCT_CONTEXT}}`:**

From the information gathered in Phase 0, build a **dynamic-only** summary.
Sub-agents read `CLAUDE.md` as their first step, so do not duplicate static architecture
or package layout information that is already documented there.

Focus on milestone-specific and Issue-specific context:

```
Current milestone: <Milestone name>
Goal: <milestone description>
Progress: <progress>%
This Issue is part of <Milestone name>, and <description of Issue's position>.

Relevant design decisions:
- <Technical decisions related to this Issue, derived from the roadmap>
```

**Building `{{DEPENDENCY_CONTEXT}}`:**

Concretely describe the outputs of completed Issues that this Issue depends on.
Helps sub-agents understand "what already exists" so they can integrate correctly.

If there are no dependencies:
```
This Issue has no preceding dependencies. Foundational type definitions and interfaces are
already defined in the scaffolding. See the package layout in CLAUDE.md.
```

If there are dependencies:
```
This Issue depends on the outputs of the following completed Issues:

### USK-XX: <title>
- Package: internal/proxy/
- Provided type: `PeekConn` (net.Conn wrapper with Peek method)
- Usage: Create PeekConn in Listener.handleConn and pass to Detector
- Key files: internal/proxy/peek_conn.go

### USK-YY: <title>
- Package: internal/session/
- Provided interface: `Store` (Save, Get, List, Delete methods)
- Usage: Inject Store into HTTP handler constructor
- Key files: internal/session/store.go, internal/session/sqlite_store.go
```

Gather dependency context information from the PRs and actual codebase of completed Issues.
Including specific type names, method signatures, and file paths lets sub-agents
integrate accurately with existing code.

**Branch name determination rules:**
- Issue labels or title contains "bug" / "fix" → `fix/`
- Otherwise → `feat/`
- Branch name: `<type>/<issue-id>-<short-desc>` (kebab-case from Issue title, max 40 chars)

**Prompt construction steps:**
1. Read `.claude/agents/implementer.md` with the Read tool
2. Extract the code block inside the `## Prompt Body` section
3. Replace placeholders with actual values
4. Pass the replaced string as the `prompt` parameter to the Task tool

#### 2-2. Wait for Batch Completion and Launch Next Batch

When all sub-agents in a batch have completed:

1. **Validate results**: Confirm success/failure of each sub-agent
2. **Merge decision for successful PRs**: If the next batch depends on a PR,
   ask the user "Would you like to merge this PR before proceeding to the next batch?"
3. **Update main**: If merged, the next batch's sub-agents work from the latest main
4. **Handle failures**: Determine whether a failed Issue blocks subsequent batches
   - If a blocker: Try to fix it, or exclude the blocked Issue from subsequent batches
   - If not a blocker: Continue with subsequent batches and address the failed Issue later
5. **Launch next batch**: Proceed to the next batch once the above is complete

#### 2-3. Parallel Launch Example

```
# Batch 1: Launch in parallel
Call multiple Task tools in the same message:
Task(description="Implement USK-XX", subagent_type="general-purpose", isolation="worktree", prompt=<prompt>)
Task(description="Implement USK-YY", subagent_type="general-purpose", isolation="worktree", prompt=<prompt>)

# Wait for Batch 1 to complete → validate results → PR merge decision

# Batch 2: Launch in parallel
Task(description="Implement USK-AA", subagent_type="general-purpose", isolation="worktree", prompt=<prompt>)
Task(description="Implement USK-BB", subagent_type="general-purpose", isolation="worktree", prompt=<prompt>)
```

---

### Phase 2.5: Review Gate

Run review gates in the background for PRs that succeeded in the batch.
Launch the entire review gate as a background Agent per PR so the orchestrator is not blocked.

#### 2.5-1. Identify Review Targets

Target Issues where a PR was created in the batch. Skip failed Issues (no PR).

#### 2.5-2. Launch Background Review Gate

Delegate the entire review → Fix → re-review cycle for each PR to **one background Agent**.
The orchestrator can proceed to the next batch preparation (merge decisions, etc.) without waiting for results.

Launch the following Agent for each PR with `run_in_background: true`:

```
Agent(
  description="Review gate PR #<N>",
  subagent_type="general-purpose",
  isolation="worktree",
  run_in_background=true,
  prompt=<review gate prompt>
)
```

**Review Gate Prompt Content:**

The prompt passed to the Agent should include:
- PR number, branch name, Issue ID
- Product context, security context
- Content of Code Review and Security Review agent templates (`.claude/agents/code-reviewer.md`, `.claude/agents/security-reviewer.md`)
- Fixer agent template (`.claude/agents/fixer.md`) content
- The following complete review gate flow steps (including Copilot review integration)

**Flow executed by the Review Gate Agent:**

**Step 0: Request Copilot Review**

Request GitHub Copilot code review immediately so it runs in parallel with Claude reviews:

```bash
gh pr edit <PR number> --add-reviewer @copilot
```

On success, record `copilot_requested = true` and `copilot_request_time`.
If the command fails (Copilot not available), log a warning and initialize defaults:

```
copilot_requested = false
copilot_findings = []
copilot_review = "UNAVAILABLE"
```

Continue without Copilot review.

**Step A: Initial Review (Parallel)**

Launch 2 Task tools in parallel in the same message:

```
Agent(description="Code review PR #<N>", subagent_type="general-purpose", isolation="worktree", prompt=<Code Review prompt>)
Agent(description="Security review PR #<N>", subagent_type="general-purpose", isolation="worktree", prompt=<Security Review prompt>)
```

Placeholder construction:
- `{{PRODUCT_CONTEXT}}` → Product context
- `{{SECURITY_CONTEXT}}` → yorishiro-proxy threat model (MITM proxy, CA key holding, MCP commands)
- `{{ISSUE_ID}}`, `{{ISSUE_DESCRIPTION}}` → Issue information
- `{{PR_NUMBER}}`, `{{PR_TITLE}}`, `{{CHANGED_FILES}}` → PR information

**Step A.5: Wait for Copilot Review**

> Skip if `copilot_requested == false`.

1. Calculate elapsed time since `copilot_request_time`
2. If less than 5 minutes have elapsed, sleep until the 5-minute mark
3. Poll for Copilot review submission:

```bash
gh api repos/{owner}/{repo}/pulls/<PR number>/reviews \
  --jq '[.[] | select(.user.login == "copilot-pull-request-reviewer")] | length'
```

- If result > 0: Collect Copilot comments → proceed to Step B
- If result == 0: Wait 1 minute and retry, up to 4 additional attempts (5 total polling attempts at approximately 5, 6, 7, 8, 9 minutes; max ~10 minutes from `copilot_request_time`)
- If no Copilot review after 5 polling attempts: Log warning, set `copilot_findings = []` and `copilot_review = "TIMED_OUT"`, proceed without Copilot findings

Collect Copilot comments:

```bash
gh api repos/{owner}/{repo}/pulls/<PR number>/comments \
  --jq '[.[] | select(.user.login == "copilot-pull-request-reviewer") | {path: .path, line: .line, body: .body}]'
```

Format as `COPILOT_FINDINGS` with severity inferred from comment content (security→HIGH, bug→MEDIUM, style→LOW).

**Step B: Aggregate Verdict**

Extract `VERDICT:` and `FINDINGS:` from each Claude agent's output, plus Copilot findings:
- Both `APPROVED` with no findings and no Copilot findings → Review complete for this PR
- Both `APPROVED` but LOW or higher findings (or Copilot findings) → Step C-1 (Fix only, no re-review)
- Either `CHANGES_REQUESTED` → Step C-2 (Fix + re-review)

**Step C-1: Fix Only (APPROVED_WITH_FINDINGS)**

If APPROVED but LOW or higher findings exist (including Copilot findings), launch Fixer once and skip re-review.

```
Agent(description="Fix LOW findings PR #<N>", subagent_type="general-purpose", isolation="worktree", prompt=<Fixer prompt>)
```

- `{{CODE_REVIEW_FINDINGS}}` → Code Review findings (all findings if present, "None" if not)
- `{{SECURITY_REVIEW_FINDINGS}}` → Security Review findings (all findings if present, "None" if not)
- `{{COPILOT_REVIEW_FINDINGS}}` → Copilot Review findings (formatted from Step A.5, "None" if not available)
- `{{BRANCH_NAME}}` → PR head branch name

After Fix, re-request Copilot review if `copilot_requested == true`:

```bash
gh pr edit <PR number> --add-reviewer @copilot
```

Review gate complete after Fix (do not wait for Copilot re-review in the fix-only path).

**Step C-2: Fix Cycle (Max 2 Rounds, CHANGES_REQUESTED)**

Launch with Fixer Agent template from `.claude/agents/fixer.md` with replaced placeholders:

```
Agent(description="Fix review findings PR #<N> round <R>", subagent_type="general-purpose", isolation="worktree", prompt=<Fixer prompt>)
```

- `{{CODE_REVIEW_FINDINGS}}` → Code Review findings (all findings including LOW if present, "None" if not)
- `{{SECURITY_REVIEW_FINDINGS}}` → Security Review findings (all findings including LOW if present, "None" if not)
- `{{COPILOT_REVIEW_FINDINGS}}` → Copilot Review findings (formatted from Step A.5, "None" if not available)
- `{{BRANCH_NAME}}` → PR head branch name

After Fix:
1. Re-run only the Claude reviews that were `CHANGES_REQUESTED`
2. Re-request Copilot review if `copilot_requested == true`:
   ```bash
   gh pr edit <PR number> --add-reviewer @copilot
   ```
3. Wait for Copilot review (same polling as Step A.5) and collect new findings
4. Include new Copilot findings in the next round's input

If not resolved after 2 rounds, report as `ESCALATED`.

**Step D: Report Results**

The Review Gate Agent returns the final result in the following format:

```
REVIEW_GATE_RESULT:
  pr_number: <N>
  code_review: APPROVED | CHANGES_REQUESTED
  security_review: APPROVED | CHANGES_REQUESTED
  copilot_review: AVAILABLE | UNAVAILABLE | TIMED_OUT
  copilot_findings_initial: <N>     # number of Copilot comments in the initial review
  copilot_findings_remaining: <N>   # number of Copilot comments in the latest re-review (0 if no re-review or unavailable)
  final_verdict: APPROVED | ESCALATED
  fix_rounds: 0 | 1 | 2
  low_fix_only: true | false
  unresolved_findings: [...]
  agent_ids: [<all sub-agent IDs launched>]
```

> **`copilot_findings_remaining`**: Determined by counting Copilot comments in the latest
> re-review round. If a re-review was performed and Copilot returned fewer comments,
> the difference represents fixed findings. If no re-review occurred, set to the same
> value as `copilot_findings_initial`.

#### 2.5-3. Collect Review Results

When a background Agent sends a completion notification, parse and record the results.
If a merge decision is needed (the next batch depends on it), wait for that PR's review to complete.

#### 2.5-4. Concurrency Strategy

| Scenario | Strategy | Concurrent Agents |
|----------|----------|------------------|
| N PRs in a batch | Launch review gates for all PRs as background simultaneously | N |
| Inside each review gate | Code + Security in parallel | 2 |
| During Fix | Fixer 1 agent only (exclusive within review gate Agent) | 1 |

#### 2.5-5. Recording Review Results

Record each PR's review result in the following format for aggregation in Phase 3:

```
pr_review_results[PR number] = {
  code_review: APPROVED | CHANGES_REQUESTED,
  security_review: APPROVED | CHANGES_REQUESTED,
  copilot_review: AVAILABLE | UNAVAILABLE | TIMED_OUT,
  copilot_findings_initial: N,
  copilot_findings_remaining: N,
  final_verdict: APPROVED | ESCALATED,
  fix_rounds: 0 | 1 | 2,
  low_fix_only: true | false,
  unresolved_findings: [...]
}
```

#### 2.5-6. Linear Status Integration

| Event | Linear Comment |
|-------|---------------|
| Review starts | "PR #N created. Automated review starting." |
| Review passes | "PR #N: Code Review APPROVED, Security Review APPROVED" |
| LOW Fix applied | "PR #N: APPROVED with LOW findings. Applying fixes." |
| Fix cycle starts | "PR #N: Review found issues. Fix round N starting." |
| Passes after Fix | "PR #N: All findings resolved after N fix round(s)." |
| Escalation | "PR #N: ESCALATION - N unresolved findings after 2 fix rounds." |

Post comments to Issues using `mcp__linear-server__create_comment`.
Linear comments are posted inside the review gate Agent.

#### 2.5-7. Handling Escalations

If there are escalated PRs:
- Continue processing other PRs in the batch
- Report unresolved finding details to the user and request manual intervention
- Leave subsequent batch execution to the user's judgment (depending on whether it is a blocker)

---

### Phase 3: Aggregate and Report Results

#### 3-1. Overall Summary

After all batches complete, aggregate results by milestone:

```markdown
## Implementation Results Summary

### Milestone: M2 — MCP Interface v2

#### Batch 1
| Issue | Title | Status | PR | Tests | Code Review | Security Review | Copilot | Fix Rounds |
|-------|-------|--------|----|-------|-------------|----------------|---------|------------|
| USK-XX | ... | Success | #4 | 8 passed | APPROVED | APPROVED | 2/2 fixed | 0 |
| USK-YY | ... | Success | #5 | 12 passed | APPROVED | Fix→APPROVED | 1/1 fixed | 1 |

#### Batch 2
| Issue | Title | Status | PR | Tests | Code Review | Security Review | Copilot | Fix Rounds |
|-------|-------|--------|----|-------|-------------|----------------|---------|------------|
| USK-AA | ... | Success | #6 | 5 passed | APPROVED | APPROVED | N/A | 0 |
| USK-BB | ... | Failed | — | 2 failed | — | — | — | — |

### Failed Issues
- **USK-BB**: ... — Test failure
  - Worktree: `/path/to/worktree` (can be checked manually)
  - Recommended: Check error logs, manually fix, or re-run

### Escalated Issues (Review not passed)
- **USK-ZZ**: ... — N unresolved findings in Security Review
  - Recommended: Manual review and fix

### Milestone Completion Status
This batch run has brought M2 to 100%.
Next milestone: M3 (Active Testing)
Continue with `/orchestrate milestone M3`.
```

If the milestone is not complete, report remaining Issues and suggest next actions.

#### 3-2. Issue Status Updates

- Implementation success + review passed: Update status to "In Review"
- Implementation success + review escalated: Update to "In Review" and record unresolved findings in comments
- Implementation failed: Keep "In Progress" and record error details with `mcp__linear-server__create_comment`

#### 3-3. Worktree Cleanup

The Claude Code Task tool does not auto-delete worktrees when they have changes after completion.
The orchestrator (caller) explicitly deletes them.

**Important**: To prevent accidentally destroying worktrees actively in use by other sessions,
do not bulk-delete. **Only target the worktrees of sub-agents you launched.**

**Steps:**

1. Record agent IDs from each Task call result in Phase 2
   (the `agentId` field in the Task tool return value)
2. In addition to the Phase 2.5 review gate Agent's agent ID,
   also collect the `agent_ids` list in the review gate Agent's output (IDs of sub-agents it launched internally)
3. After all batches and review cycles complete, run the following for each recorded agent ID:

```bash
git worktree remove .claude/worktrees/agent-<agentId> --force 2>/dev/null || true
```

3. Clean up metadata after all deletions:

```bash
git worktree prune
```

- Delete all worktrees you launched regardless of success/failure (changes are pushed to remote)
- Debug information for failed Issues is accessible via Linear comments and `git checkout <branch-name>`
- `git worktree remove` only deletes the directory; branches and commits are preserved

#### 3-4. Suggest Next Steps

Suggest the next executable milestone/batch.

---

## Dependency Analysis Guidelines

### Inter-Milestone Dependencies (Dynamic analysis based on roadmap)

Read the dependency information from the milestone sections of the roadmap document
and determine dependency satisfaction from milestone progress.

- `progress == 100` → Dependency satisfied. Can proceed to subsequent milestone Issues
- `0 < progress < 100` → Partially satisfied. May be able to proceed depending on remaining Issue content
- `progress == 0` → Not satisfied. Prerequisite milestone goes first

### Intra-Milestone Dependency Inference Rules

1. **Infrastructure/utility Issues go first**: Foundational items like buffered readers and storage layers
2. **Handlers/business logic in the middle**: Logic built on top of the foundation
3. **Integration/combining Issues later**: Issues that connect multiple components go after dependencies are ready
4. **E2E tests/integration tests last**: After all components are in place
5. **MCP tool definitions after corresponding internal implementations**: Expose tools after the internal API is finalized

### Criteria for Parallel Execution

**Can run in parallel:**
- Primarily modify different packages (e.g., `internal/proxy/` and `internal/session/`)
- Implement a common interface but do not call each other
- Tests do not depend on each other's implementations

**Must run sequentially:**
- Issue B imports types or interfaces generated by Issue A
- Issue B's tests assume Issue A's implementation
- Issue B modifies the same part of a file changed by Issue A

---

## Notes

- Maximum concurrent executions: up to 3 Issues (due to resource constraints)
- Always load the latest roadmap (do not cache)
- Do not implement across milestones as a general rule (proceed to the next after the previous milestone's PRs are merged)
- Each sub-agent operates completely independently — no cross-references
- Linear Issue status updates are the orchestrator's responsibility (sub-agents do not do this)
- If you are not confident in the dependency analysis result, confirm with the user
