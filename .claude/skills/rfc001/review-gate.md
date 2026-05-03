# RFC-001 Phase 4 — Review Gate (lazy-loaded)

Loaded by `/rfc001` SKILL.md only when Phase 4-1 determines review is required (mandatory N2 / milestone-final issue) or the user opts in for non-mandatory issues. Holds the prompt construction, verdict handling, and worktree cleanup steps that don't need to live in the main SKILL.md.

> **Phase 4-1 (gate decision) stays in SKILL.md.** This file picks up at 4-2.

## 4-2. Build Review Context

1. Read `.claude/skills/rfc001/review-context.md` — contains the **product context** and **security context** blocks. Substitute `<X>` (milestone identifier) and `<milestone description>` placeholders.
2. Read agent templates with the Read tool:
   - `.claude/agents/code-reviewer.md`
   - `.claude/agents/security-reviewer.md`
   - `.claude/agents/fixer.md`

## 4-3. Launch Review Gate Agent

Read `.claude/skills/review-gate/SKILL.md` at invocation time and include its **full content** in the sub-agent prompt.

```
Agent(
  description="Review gate PR #<N> (RFC-001)",
  subagent_type="general-purpose",
  isolation="worktree",
  prompt=<review gate prompt>
)
```

The prompt must include:
- Full content of `/review-gate` SKILL.md
- PR number, head branch (`rfc001/<issue-id>-<short-desc>`), base branch (`rewrite/rfc-001`)
- Issue ID
- Product + security context (from `review-context.md`, substituted)
- Content of the three agent templates (code-reviewer, security-reviewer, fixer)

> **Single Source of Truth**: Do not duplicate the review-gate flow steps in this skill. Always read the SKILL.md at prompt construction time.

**Expected output format**:

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

## 4-4. Handle Verdict

| Verdict | Action |
|---|---|
| **APPROVED** | Proceed to Phase 5. Record `fix_rounds` for the report. |
| **ESCALATED** | Report unresolved findings. **Do not merge.** Ask whether to proceed to Phase 5 (with issue noted) or stop. |

## 4-5. Worktree Cleanup

Collect all agent IDs returned by the review gate (its own + `agent_ids`):

```bash
git worktree remove .claude/worktrees/agent-<agentId> --force 2>/dev/null || true
git worktree prune
```

Only target worktrees of sub-agents launched in this session.
