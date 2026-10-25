# Implementer Sub-Agent Prompt Template

This file is used as the prompt parameter for the Task tool by the `/orchestrate` skill.

## Placeholders

The orchestrator replaces the following with actual values:

- `{{ISSUE_ID}}`, `{{ISSUE_TITLE}}`, `{{ISSUE_DESCRIPTION}}`, `{{ISSUE_LABELS}}`
- `{{BRANCH_NAME}}`, `{{BRANCH_TYPE}}`
- `{{PRODUCT_CONTEXT}}` — Product overview, current phase, summary of relevant design decisions
- `{{DEPENDENCY_CONTEXT}}` — Outputs of completed Issues this Issue depends on, and the types/interfaces they provide
- `{{DESIGN_REVIEW_CONTEXT}}` — Findings from the Phase 1.5 design review (resolved decisions, boundary survey, fitness check). Or a one-line skip notice for trivial Issues.

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

## Design Review Findings

{{DESIGN_REVIEW_CONTEXT}}

The design review above is the authoritative pre-implementation analysis for this Issue. Its
**Resolved Decisions** are the decisions you must follow — do not re-litigate them. Its
**Boundary Survey** tells you which existing types/interfaces/data flows the new code must
integrate with. If a question is not in the table, fall back to first principles (CLAUDE.md
MITM Implementation Principles) — do not invent a new approach that contradicts the resolved
decisions.

If the design review was skipped (you will see a one-line skip notice), implement directly
per the Issue description while still adhering to CLAUDE.md conventions.

If the findings include a **Test Plan**, it is the list of failing tests you write in TDD
Phase 1 below. You may add tests to it; do not drop one without saying why in the PR body.

## First Steps

1. Read `CLAUDE.md` at the project root to understand coding conventions and architecture
2. Read the "Product Context", "Dependency Context", and "Design Review Findings" above to understand where your Issue fits in the overall product and which decisions are already locked in
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

## TDD Workflow (mandatory)

This project develops test-first. The point is not ceremony: a test that has never been seen
failing has not been shown to detect anything. Tests written after the implementation tend to
be fitted to it, drive a simulated producer instead of the real one, or use fixtures in a shape
the real API never returns — every one of those has let a real bug through here before.

Work in three phases, with the first phase committed on its own.

### Phase 1 — Red: failing tests first

1. From the Issue's acceptance criteria and the design review's Test Plan, write the tests
   **before** any production code. Each test states one behavior the Issue requires.
2. Drive the **real** code path: call the real producer/entry point, not a hand-built terminal
   state. Build fixtures from a shape the real wire/API produces (cite where you took it from).
   For MITM data-path behavior, assert recording outcomes (Stream/Flow/raw bytes), not merely
   that bytes flowed.
3. Add only the minimum production scaffolding needed to **compile** (new type, function stub
   returning zero values / `errors.New("not implemented")`). No behavior.
4. Run the targeted tests and confirm they fail **for the reason the test describes** — an
   assertion failure, not a compile error, panic in setup, or `no tests to run`:
   ```bash
   make test-pkg PKG=./internal/<pkg>/... RUN='TestName_Scenario|TestOther'
   # e2e test? add TAGS=e2e
   ```
   Check the output names each new test under `--- FAIL:`. If a test passes already, either the
   behavior exists (re-read the Issue premise and report it) or the test does not test it.
5. Commit only the tests and the scaffolding:
   ```
   test(<scope>): add failing tests for {{ISSUE_ID}}

   Refs: {{ISSUE_ID}}
   ```
   Save the trimmed `--- FAIL:` lines (test name + assertion message) for the PR body.

**Exempt from Phase 1** (state the exemption in the PR body under "TDD evidence"):
- docs-only, comment-only, CI/workflow-only, or pure rename changes
- behavior-preserving refactors — instead, confirm the existing tests covering the touched code
  pass **before** you change it; if none cover it, first commit characterization tests that pin
  today's behavior (these pass, and that is the point)
- test-only Issues (e.g. adding e2e coverage) — instead, prove each new test can fail: break the
  behavior it covers locally (mutation), see it fail, revert the mutation, and report it

### Phase 2 — Green: implement until the tests pass

- Write the production code to make the Phase 1 tests pass. Re-run `make test-pkg` as you go.
- **Do not weaken, delete, or rewrite a Phase 1 assertion to make it pass.** If a Phase 1 test
  was genuinely wrong (it encoded a misreading of the Issue), fix it in a separate commit
  `test(<scope>): correct <test> expectation` and explain why in the PR body. Reviewers diff the
  test files between the Phase 1 commit and HEAD and treat unexplained weakening as HIGH.
- If the implementation reveals behavior the Issue needs but Phase 1 did not cover, write that
  test first, see it fail, then make it pass.

### Phase 3 — Refactor

With everything green, clean up production and test code without changing behavior, then run
the full verification below.

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

After Phase 3, run the following in order and confirm everything passes:

```bash
gofmt -w .
make lint
make build
make test
```

If `web/` changed, also run `make test-ui` and `make lint-ui` (eslint, `--max-warnings 0`).

- Auto-format with `gofmt -w .`
- `make lint` runs a `gofmt -l .` check, then `golangci-lint run`
  (govet / staticcheck / unused / ineffassign / gocyclo, configured in `.golangci.yml`)
- `make lint` hard-fails if `golangci-lint` is missing from PATH or is not the
  version pinned in `.golangci-lint-version`; it prints the install command.
  Do **not** `go install` golangci-lint — use the official `install.sh`
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

Keep the Phase 1 `test(...)` commit separate from the implementation commit(s) — do not squash
or amend them together. The PR is squash-merged, so the red commit never lands on `main`; it
exists so reviewers can check out the red state and re-run it.

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

## TDD evidence
- Red commit: <sha of the Phase 1 test commit> (or: exempt — <reason>)
- Failing output at the red commit:
  ```
  --- FAIL: TestX_Scenario ... <assertion message>
  ```
- Phase 1 test changes after the red commit: none (or: <commit> — <why the expectation was wrong>)

Resolves {{ISSUE_ID}}
Linear: https://linear.app/usk6666/issue/{{ISSUE_ID}}

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

## Final Checklist

Confirm the following before completing implementation:

- [ ] All Issue requirements are satisfied
- [ ] Failing tests were committed first and observed failing for the stated reason (or the exemption is stated)
- [ ] No Phase 1 assertion was weakened; any corrected expectation has its own commit and explanation
- [ ] The PR body has the "TDD evidence" section
- [ ] `make lint` passes completely (gofmt check + golangci-lint: govet, staticcheck, unused, ineffassign, gocyclo)
- [ ] `make build` succeeds
- [ ] `make test` passes completely
- [ ] If `web/` changed: `make test-ui` and `make lint-ui` pass
- [ ] Commit message is in Conventional Commits format
- [ ] PR is created with an appropriate description
- [ ] No unnecessary files included (debug output, temp files)
- [ ] If new external dependencies are added, their license is in the allowed list
- [ ] The feature is accessible from the config file (no missing config struct, validation, or init function changes)

## Output

After completing the work, report the following as the final message:

1. **Implementation Summary**: Overview of what was implemented
2. **Created/Modified File List**: Paths and roles of each file
3. **Test Summary**: Test count, coverage information, red commit SHA and the tests it showed failing
4. **PR URL**: URL of the created PR
5. **Notes**: Points to focus on during review, known limitations

**Note**: After PR creation, the orchestrator will automatically run Code Review Agent and Security Review Agent reviews.
Therefore, no additional self-review or quality checks are needed.
Passing `make build` / `make test` verification is sufficient.
```
