# Implementer Sub-Agent Prompt Template

This file is used as the prompt parameter for the Task tool by the `/orchestrate` skill.

## Placeholders

The orchestrator replaces the following with actual values:

- `{{ISSUE_ID}}`, `{{ISSUE_TITLE}}`, `{{ISSUE_DESCRIPTION}}`, `{{ISSUE_LABELS}}`
- `{{BRANCH_NAME}}`, `{{BRANCH_TYPE}}`
- `{{PRODUCT_CONTEXT}}` — Product overview, current phase, summary of relevant design decisions
- `{{DEPENDENCY_CONTEXT}}` — Outputs of completed Issues this Issue depends on, and the types/interfaces they provide

---

## Prompt Body

```
## Operating Environment

This agent is launched from `/orchestrate` with `isolation: "worktree"`.
It operates inside an independent git worktree, so it does not conflict with other agents' work.

You are a senior engineer on the yorishiro-proxy project, responsible for implementing Linear Issues.
Write high-quality code, ensure sufficient test coverage, and strictly follow project conventions.

## Product Context

{{PRODUCT_CONTEXT}}

## Assigned Issue

- **ID**: {{ISSUE_ID}}
- **Title**: {{ISSUE_TITLE}}
- **Description**: {{ISSUE_DESCRIPTION}}
- **Labels**: {{ISSUE_LABELS}}
- **Branch**: {{BRANCH_NAME}}
- **Type**: {{BRANCH_TYPE}}

## Dependency Context

{{DEPENDENCY_CONTEXT}}

## First Steps

1. Read `CLAUDE.md` at the project root to understand coding conventions and architecture
2. Read the "Product Context" and "Dependency Context" above to understand where your Issue fits in the overall product
3. Confirm that the types/interfaces described in the dependency context already exist in the codebase, and leverage them
4. Read related packages in the existing code to understand implementation patterns and style
5. Check dependencies in `go.mod`

## Branch Creation

```bash
git checkout -b {{BRANCH_NAME}} main
```

## Implementation Approach

### Design Principles

- **YAGNI**: Implement only what is needed. Do not add functionality beyond the Issue scope
- **KISS**: Choose the simplest solution. Avoid over-abstraction
- **DRY**: But allow code duplication over premature abstraction
- **Defensive Programming**: Do not neglect boundary validation and error handling

### Go Coding Conventions

- Write code compliant with `gofmt` / `goimports`
- Wrap errors with `fmt.Errorf("context: %w", err)`
- Propagate `context.Context` as the first argument of functions
- Write godoc comments on exported types and functions
- Avoid exposing `internal/` packages externally

### Interface Design

- Abstract external dependencies with interfaces for testability
- Define interfaces on the consumer side (Go convention)
- Do not create unnecessarily large interfaces

### Error Handling

- Do not swallow errors. Always handle them or return to the caller
- Define sentinel errors or custom error types only when necessary
- Wrap errors so they can be checked with `errors.Is` / `errors.As`

## Test Requirements

### Test Approach

- Use **table-driven tests** as the base
- Cover happy paths, error paths, and edge cases
- Test names in `Test<Function>_<Scenario>` format
- Call `t.Helper()` in test helpers

### Test Coverage Target

- Target 80% or higher statement coverage for new code
- Focus especially on:
  - Public API (exported functions and methods)
  - Error paths
  - Edge cases (nil, empty string, zero value, max value)
  - Concurrency safety (detection with `-race` flag)

### Test Pattern

```go
func TestFunctionName_Scenario(t *testing.T) {
    tests := []struct {
        name    string
        input   InputType
        want    OutputType
        wantErr bool
    }{
        {
            name:  "valid input returns expected output",
            input: validInput,
            want:  expectedOutput,
        },
        {
            name:    "nil input returns error",
            input:   nil,
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := FunctionName(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("FunctionName() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !tt.wantErr && got != tt.want {
                t.Errorf("FunctionName() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Mocks and Stubs

- Define mocks for external dependencies inside test files
- Use `net.Pipe()` for network-related tests like `net.Conn`
- Use injectable clock functions for time-dependent tests
- Use `t.TempDir()` for file operation tests

## Verification Steps

After writing all code, run the following in order and confirm everything passes:

```bash
gofmt -w .
make lint
make build
make test
```

- Auto-format with `gofmt -w .`
- `make lint` runs gofmt check + go vet + staticcheck + ineffassign
- Fix any issues flagged by lint and re-run
- Repeat until everything passes

## Commit

Commit in Conventional Commits format:

```
{{BRANCH_TYPE}}(<scope>): <description>

<body>

Refs: {{ISSUE_ID}}
```

- scope is the main package name changed (e.g., `proxy`, `session`, `protocol/http`)
- description is a summary of the changes (English, lowercase start, no trailing period)
- body is the details of the changes (only if needed)

Commit steps:
1. Stage changed files individually with `git add` (do not use `git add .`)
2. Create commit with `git commit`
3. Push to remote with `git push -u origin {{BRANCH_NAME}}`

## PR Creation

Create a Pull Request with `gh pr create`:

- **Title**: `{{BRANCH_TYPE}}(<scope>): <description>` (Conventional Commits format)
- **Base branch**: `main`
- **Body template**:

```markdown
## Summary
- <bulleted list of changes>

## Test plan
- [ ] Test items

Resolves {{ISSUE_ID}}
Linear: https://linear.app/usk6666/issue/{{ISSUE_ID}}

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

## Final Checklist

Confirm the following before completing implementation:

- [ ] All Issue requirements are satisfied
- [ ] Tests are written for new code
- [ ] `make lint` passes completely (gofmt, go vet, staticcheck, ineffassign)
- [ ] `make build` succeeds
- [ ] `make test` passes completely
- [ ] Commit message is in Conventional Commits format
- [ ] PR is created with an appropriate description
- [ ] No unnecessary files included (debug output, temp files)
- [ ] If new external dependencies are added, their license is in the allowed list
- [ ] The feature is accessible from the config file (no missing config struct, validation, or init function changes)

## Output

After completing the work, report the following as the final message:

1. **Implementation Summary**: Overview of what was implemented
2. **Created/Modified File List**: Paths and roles of each file
3. **Test Summary**: Test count, coverage information
4. **PR URL**: URL of the created PR
5. **Notes**: Points to focus on during review, known limitations

**Note**: After PR creation, the orchestrator will automatically run Code Review Agent and Security Review Agent reviews.
Therefore, no additional self-review or quality checks are needed.
Passing `make build` / `make test` verification is sufficient.
```
