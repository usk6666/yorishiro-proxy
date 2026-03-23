---
description: "Load a Linear Issue and execute the full workflow from branch creation to implementation, testing, commit, and PR creation"
user-invokable: true
---

# /implement

An end-to-end workflow skill for implementing a Linear Issue through to PR creation.

## Arguments

- `/implement <Issue ID>` — Implement the specified Issue (e.g., `/implement USK-12`)

## Steps

1. **Load Issue**: Fetch Issue details with `mcp__linear-server__get_issue`
2. **Update Issue status**: Update status to "In Progress"
3. **Create branch**: Generate an appropriate branch name from the Issue
   - feat: `feat/<id>-<short-desc>`
   - fix: `fix/<id>-<short-desc>`
   - other: `chore/<id>-<short-desc>`
4. **Implementation plan**: Analyze Issue content and create an implementation plan
5. **Implement**: Implement code based on the plan
6. **Write tests**: Write tests for the implementation
7. **Verify**:
   - Auto-format with `gofmt -w .`
   - `make lint` (gofmt check + go vet + staticcheck + ineffassign)
   - `make build`
   - `make test`
8. **Commit**: Commit in Conventional Commits format
   - Include `Refs: <Issue ID>` in the commit message footer
9. **Push**: Push to remote with `git push -u origin <branch-name>`
10. **Create PR**:
    - Review changes with `git diff main...HEAD`
    - PR title in Conventional Commits format (e.g., `feat(protocol): add HTTP handler`)
    - PR body follows the template below
    - Create PR with `gh pr create`
11. **Update Issue status**: Update status to "In Review"
12. **Report results**: Display implementation summary + PR URL

## PR Body Template

```markdown
## Summary
- <bulleted list of changes>

## Test plan
- [ ] Test items

Resolves <Issue ID>
Linear: https://linear.app/usk6666/issue/<Issue ID>

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

## Notes

- If build or tests fail, fix the issues before re-running
- Determine implementation scope from Issue labels and description
- For large changes, create a plan and confirm with the user before proceeding
- Since build/test verification was done in Step 7, do not re-run when creating the PR
- If PR creation fails, guide the user to manually run `/pr`
- Before completing implementation, verify that the feature is accessible from the config file (no missing config struct, validation, or init function changes)
