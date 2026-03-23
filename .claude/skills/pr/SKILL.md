---
description: "Create a PR. Verify build and test pass, then run gh pr create"
user-invokable: true
---

# /pr

A skill for creating Pull Requests.

## Steps

1. **Build verification**: Run `make build` and confirm no errors
2. **Run tests**: Run `make test` and confirm all tests pass
3. **Review diff**: Check changes with `git diff main...HEAD`
4. **Generate PR title**: Create a title in Conventional Commits format (`feat(scope): description`)
5. **Generate PR body**: Generate body including a summary of changes and test plan
6. **Create PR**: Run `gh pr create --title "<title>" --body "<body>"`
7. **Display result**: Show the PR URL

## PR Body Template

```markdown
## Summary
- <bulleted list of changes>

## Test plan
- [ ] Test items

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

## Notes

- If build or tests fail, do not create the PR and report the problem instead
- Default base branch is `main`
