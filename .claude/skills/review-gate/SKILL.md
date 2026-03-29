---
description: "Gate skill for managing the PR review → Fix → re-review cycle. Run Code Review + Security Review + Copilot Review in parallel, and auto-fix if issues are found"
user-invokable: true
---

# /review-gate

A gate skill that runs code review and security review in parallel for a PR,
and if issues are found, executes an auto-fix → re-review cycle for up to 2 rounds.

## Argument Patterns

- `/review-gate <PR number>` — Run full review cycle on the specified PR
- `/review-gate <PR number> --issue <ISSUE_ID>` — Explicitly specify Issue ID
- `/review-gate` — Run full review cycle on the PR associated with the current branch

---

## Steps

### Phase 1: Collect PR Information

#### 1-1. Identify the PR

If an argument is provided:
- Use `<PR number>`

If no argument is provided:
- Get the PR number for the current branch with `gh pr view --json number -q .number`

#### 1-2. Fetch PR Information

Fetch the following **in parallel**:

```bash
gh pr view <PR number> --json title,body,headRefName,baseRefName,number,url
gh pr diff <PR number> --name-only
```

#### 1-3. Fetch Issue Information

If `--issue` is specified, use that.
Otherwise, extract the Issue ID in `USK-XX` format from the PR body,
and fetch details with `mcp__linear-server__get_issue`.

#### 1-4. Build Context

**Product context:**
```
yorishiro-proxy is a network proxy (MCP server) for AI agents.
Provides traffic interception, recording, and replay capabilities for vulnerability assessment.
Architecture: TCP Listener → Protocol Detection → Protocol Handler → Session Recording → MCP Tool
```

**Security context:**
```
yorishiro-proxy operates as a MITM proxy, therefore:
- It directly processes attacker-controlled traffic
- It holds the CA private key and dynamically issues certificates
- Session recordings may contain credentials (auth tokens, passwords)
- AI agents execute commands via MCP
```

---

### Phase 1.5: Request Copilot Review

Request GitHub Copilot code review immediately so it runs in parallel with Claude reviews.

```bash
gh pr edit <PR number> --add-reviewer @copilot
```

If this fails (e.g., Copilot not available on the repo), log a warning and continue without Copilot review.
Record `copilot_requested = true | false` and `copilot_request_time` (timestamp of the request).

---

### Phase 2: Run Reviews in Parallel

#### 2-1. Load Agent Templates

Read `.claude/agents/code-reviewer.md` and `.claude/agents/security-reviewer.md` with the Read tool,
and extract the code block inside each template's `## Prompt Body` section.

#### 2-2. Replace Placeholders

**Code Review Agent:**
- `{{PR_NUMBER}}` → PR number
- `{{PR_TITLE}}` → PR title
- `{{ISSUE_ID}}` → Issue ID
- `{{ISSUE_DESCRIPTION}}` → Issue description
- `{{PRODUCT_CONTEXT}}` → Product context
- `{{CHANGED_FILES}}` → List of changed files

**Security Review Agent:**
- `{{PR_NUMBER}}` → PR number
- `{{PR_TITLE}}` → PR title
- `{{ISSUE_ID}}` → Issue ID
- `{{PRODUCT_CONTEXT}}` → Product context
- `{{SECURITY_CONTEXT}}` → Security context

#### 2-3. Parallel Launch

Launch 2 Task tools **in the same message** in parallel:

```
Task(description="Code review PR #<N>", subagent_type="general-purpose", isolation="worktree", prompt=<Code Review prompt>)
Task(description="Security review PR #<N>", subagent_type="general-purpose", isolation="worktree", prompt=<Security Review prompt>)
```

**Note**: Reviews are read-only, but `isolation: "worktree"` is used because checking out the target branch during parallel execution conflicts with the main worktree state.

---

### Phase 2.5: Wait for and Collect Copilot Review

> **Skip this phase** if `copilot_requested == false`.

#### 2.5-1. Calculate Wait Time

Copilot review typically takes 3-5 minutes. Wait strategy:

1. Calculate elapsed time since `copilot_request_time`
2. If less than 5 minutes have elapsed, sleep until the 5-minute mark
3. After 5 minutes, check if Copilot review has been submitted

#### 2.5-2. Poll for Copilot Review

Check for Copilot review submission:

```bash
gh api repos/{owner}/{repo}/pulls/<PR number>/reviews \
  --jq '[.[] | select(.user.login == "copilot-pull-request-reviewer")] | length'
```

- If result > 0: Copilot review has been submitted → proceed to 2.5-3
- If result == 0: Wait 1 minute and retry (max 5 retries = 10 minutes total from request)
- If max retries exceeded: Log warning "Copilot review timed out" and proceed without Copilot findings

#### 2.5-3. Collect Copilot Review Comments

Fetch Copilot's review comments:

```bash
gh api repos/{owner}/{repo}/pulls/<PR number>/comments \
  --jq '[.[] | select(.user.login == "copilot-pull-request-reviewer") | {path: .path, line: .line, body: .body}]'
```

Also fetch the review body (top-level review summary):

```bash
gh api repos/{owner}/{repo}/pulls/<PR number>/reviews \
  --jq '[.[] | select(.user.login == "copilot-pull-request-reviewer")] | last | {state: .state, body: .body}'
```

Record findings as:

```
copilot_review_state = APPROVED | CHANGES_REQUESTED | COMMENTED
copilot_findings = [{ path, line, body }, ...]
```

---

### Phase 3: Aggregate Verdict

#### 3-1. Parse Results

Extract `VERDICT:` lines from each agent's output and record the verdict.

```
code_review_verdict = APPROVED | CHANGES_REQUESTED
security_review_verdict = APPROVED | CHANGES_REQUESTED
```

#### 3-2. Check for Findings

Parse the `FINDINGS:` section from each Claude agent's output and record whether LOW or higher findings exist.
`FINDINGS: None` means no findings.

```
code_review_has_findings = true | false
security_review_has_findings = true | false
copilot_has_findings = len(copilot_findings) > 0  # from Phase 2.5
has_any_findings = code_review_has_findings or security_review_has_findings or copilot_has_findings
```

#### 3-3. Format Copilot Findings for Fix

Convert Copilot review comments into a format compatible with the Fixer Agent:

```
COPILOT_FINDINGS:
  - ID: C-1, Severity: MEDIUM, File: <path>, Line: <line>
    Description: <comment body>
  - ID: C-2, ...
```

Severity mapping for Copilot comments:
- Comments suggesting security fixes → HIGH
- Comments suggesting bug fixes → MEDIUM
- Style/refactoring suggestions → LOW
- Use your judgment based on the comment content

#### 3-4. Aggregate Verdict

| Code Review | Security Review | Copilot Review | Aggregate Verdict | Next Action |
|-------------|----------------|----------------|-------------------|-------------|
| APPROVED (no findings) | APPROVED (no findings) | No findings / N/A | **APPROVED** | Phase 5 (Report) |
| APPROVED | APPROVED | Has findings | **APPROVED_WITH_FINDINGS** | Phase 4 (Fix only, no re-review) |
| APPROVED (with findings) | APPROVED (no/with findings) | Any | **APPROVED_WITH_FINDINGS** | Phase 4 (Fix only, no re-review) |
| Any CHANGES_REQUESTED | Any | Any | **CHANGES_REQUESTED** | Phase 4 (Fix + re-review) |

> **Note**: Copilot findings alone do not trigger `CHANGES_REQUESTED` — they are always treated as supplementary.
> However, if Copilot's review state is `CHANGES_REQUESTED`, it contributes to the aggregate verdict.

---

### Phase 4: Fix Cycle (Max 2 Rounds)

> **Note**: For `APPROVED_WITH_FINDINGS`, run Fixer once only and skip re-review.
> The re-review cycle (max 2 rounds) applies only for `CHANGES_REQUESTED`.

#### 4-1. Launch Fixer Agent

Read `.claude/agents/fixer.md` with the Read tool and replace placeholders:

- `{{PR_NUMBER}}` → PR number
- `{{BRANCH_NAME}}` → PR head branch name
- `{{CODE_REVIEW_FINDINGS}}` → Code Review findings (pass all findings if present; "None — Code review passed." if none)
- `{{SECURITY_REVIEW_FINDINGS}}` → Security Review findings (pass all findings if present; "None — Security review passed." if none)
- `{{COPILOT_REVIEW_FINDINGS}}` → Copilot Review findings formatted in Phase 3-3 (pass all findings if present; "None — Copilot review not available or no findings." if none)
- `{{ORIGINAL_ISSUE_ID}}` → Issue ID
- `{{PRODUCT_CONTEXT}}` → Product context

Launch with Task tool:
- `subagent_type`: `"general-purpose"`
- `isolation`: `"worktree"`
- `description`: `"Fix review findings PR #<N> round <R>"`
- `prompt`: Replaced prompt

#### 4-2. Check Fix Results

Extract the status of each finding from the Fixer Agent output:
- `FIXED`: Fix complete
- `PARTIALLY_FIXED`: Partially fixed
- `UNRESOLVED`: Not resolved

#### 4-3. Re-review

Re-run **only the reviews that were `CHANGES_REQUESTED`**:

- Only Code Review was `CHANGES_REQUESTED` → Re-launch Code Review Agent only
- Only Security Review was `CHANGES_REQUESTED` → Re-launch Security Review Agent only
- Both were `CHANGES_REQUESTED` → Re-launch both in parallel

#### 4-4. Round Management

```
# For APPROVED_WITH_FINDINGS: Fix only, no re-review
if aggregate_verdict == APPROVED_WITH_FINDINGS:
    Launch Fixer Agent (pass all findings including LOW + Copilot findings)
    → Phase 4.5 (Copilot re-review) → Phase 5

# For CHANGES_REQUESTED: Fix + re-review cycle (max 2 rounds)
current_round = 1

while current_round <= 2:
    if aggregate_verdict == APPROVED or aggregate_verdict == APPROVED_WITH_FINDINGS:
        break  → Phase 4.5 → Phase 5

    Launch Fixer Agent (pass all findings including LOW + Copilot findings)
    Run re-review (only the side that was CHANGES_REQUESTED)
    → Phase 4.5 (Copilot re-review on each round)
    Aggregate verdict (including new Copilot findings)

    current_round += 1

if current_round > 2 and aggregate_verdict == CHANGES_REQUESTED:
    → ESCALATE
```

#### 4-5. Copilot Re-review After Fix

> **Skip this step** if `copilot_requested == false`.

After the Fixer Agent pushes changes, re-request Copilot review and wait for new results.

**Step 1: Re-request Copilot review**

```bash
gh pr edit <PR number> --add-reviewer @copilot
```

> **Note**: GitHub CLI supports re-requesting Copilot review via `--add-reviewer @copilot`
> even after a previous review has been submitted.

**Step 2: Wait for new Copilot review**

Same polling strategy as Phase 2.5:
- Wait 5 minutes from the re-request
- Poll every 1 minute (max 5 retries)
- Check that the latest Copilot review is newer than the fix commit

```bash
# Get the latest Copilot review timestamp
gh api repos/{owner}/{repo}/pulls/<PR number>/reviews \
  --jq '[.[] | select(.user.login == "copilot-pull-request-reviewer")] | last | .submitted_at'
```

Compare against the fix commit timestamp. Only collect comments from the latest review.

**Step 3: Collect new Copilot findings**

Fetch new Copilot comments (same as Phase 2.5-3) and update `copilot_findings`.
New Copilot findings are included in the next fix round's input (if another round occurs)
or reported in Phase 5 (if no more rounds).

---

### Phase 5: Report Results

#### 5-1. Final Status

| Result | Meaning |
|--------|---------|
| **APPROVED** | Both reviews passed (initial or after Fix) |
| **ESCALATED** | Review not passed after 2 rounds of fixes. Manual intervention required |

#### 5-2. Report to User

```markdown
## Review Gate Results: PR #<N>

**Final Verdict**: APPROVED / ESCALATED
**PR**: <PR URL>
**Fix Rounds**: 0 / 1 / 2

### Review Results

| Review | Initial | Round 1 | Round 2 | Final |
|--------|---------|---------|---------|-------|
| Code Review | APPROVED/CHANGES_REQUESTED | — | — | APPROVED |
| Security Review | CHANGES_REQUESTED | APPROVED | — | APPROVED |
| Copilot Review | 3 comments | 1 comment | — | 0 comments |

### Findings Summary

| ID | Severity | Category | Status |
|----|----------|----------|--------|
| F-1 | HIGH | Correctness | FIXED (Round 1) |
| S-1 | MEDIUM | InputValidation | FIXED (Round 1) |

### Escalation (ESCALATED only)

The following findings could not be resolved in 2 rounds of fixes. Manual intervention requested:

| ID | Severity | File | Description |
|----|----------|------|-------------|
| ... | ... | ... | ... |
```

#### 5-3. Update Linear Status (if Issue ID exists)

| Event | Linear Comment |
|-------|---------------|
| Review passed | "PR #N: Code Review APPROVED, Security Review APPROVED" |
| Fix cycle starts | "PR #N: Review found issues. Fix round 1 starting." |
| Passes after Fix | "PR #N: All findings resolved after N fix round(s)." |
| Escalation | "PR #N: ESCALATION - N unresolved findings after 2 fix rounds. Manual intervention needed." |

Post comments to Issues using `mcp__linear-server__create_comment`.

### Phase 6: Worktree Cleanup

After the review cycle completes, delete **only the worktrees of sub-agents you launched**.

**Important**: To prevent accidentally destroying worktrees actively in use by other sessions,
do not bulk-delete.

**Steps:**

1. Record agent IDs from each Task call in Phases 2 through 4
2. Run the following for each recorded agent ID:

```bash
git worktree remove .claude/worktrees/agent-<agentId> --force 2>/dev/null || true
```

3. Clean up metadata after all deletions:

```bash
git worktree prune
```

Note: When called from `/orchestrate`, bulk deletion happens in Phase 3-3, so there may be duplication,
but it is idempotent so no problem. This effectively functions only when `/review-gate` is run standalone.

---

## Concurrency Strategy

| Scenario | Strategy | Concurrent Agents |
|----------|----------|------------------|
| Initial review | Code + Security in parallel | 2 |
| Re-review (one side only) | Single execution | 1 |
| Re-review (both sides) | Code + Security in parallel | 2 |
| Fix | Fixer 1 agent only | 1 |

## Maximum Agent Calls Per PR (Worst Case)

Initial review 2 + Fix 1 + Re-review 2 + Fix 1 + Re-review 2 = **8 calls** (unchanged; Copilot uses `gh` CLI, not Agent calls)
For APPROVED_WITH_FINDINGS: Initial review 2 + Fix 1 = **3 calls**

> **Note**: Copilot review request/polling uses `gh` CLI commands, not additional Agent calls.
> The wait time adds ~5-10 minutes per round but does not increase agent concurrency.

---

## Notes

- Review agents are **read-only** — they make no code changes whatsoever
- Fixer Agent operates in a **worktree** — directly modifies the PR branch
- **LOW and above** findings are all fix targets (NIT only is excluded)
- Even if APPROVED, launch Fixer if LOW findings exist (no re-review needed)
- On escalation, do not attempt fixes; defer to the user's judgment
