BINARY := yorishiro-proxy
BINDIR := bin
MODULE := github.com/usk6666/yorishiro-proxy
DIST_DIR := internal/mcp/webui/dist

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

# Pinned golangci-lint version. Single source of truth: .golangci-lint-version,
# which CI consumes via golangci-lint-action's `version-file` input, so the
# local and CI rule sets cannot drift.
#
# The `lint` recipe validates the file's shape (`vX.Y[.Z]`, one line) before
# using this value, so a missing / empty / CRLF / malformed file produces a
# named error instead of an empty substitution. The check lives in the recipe
# rather than a parse-time `$(error ...)` so that an unrelated target such as
# `make clean` still works when the file is broken.
GOLANGCI_LINT_VERSION := $(shell cat .golangci-lint-version 2>/dev/null)

.PHONY: build build-ui ensure-ui dev-ui test test-fast test-ui test-e2e test-e2e-smoke test-cover vet lint fmt clean bench bench-compare

build: build-ui vet
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(BINARY) ./cmd/yorishiro-proxy

build-ui:
	cd web && pnpm install --frozen-lockfile && pnpm run build

ensure-ui:
	@if [ ! -d $(DIST_DIR) ]; then $(MAKE) build-ui; fi

dev-ui:
	cd web && pnpm run dev

test-ui:
	cd web && pnpm install --frozen-lockfile && pnpm test

# test runs the fast tier: untagged unit tests only. Used as the per-PR gate.
test: ensure-ui
	go test -race -v -timeout 4m ./...

# test-fast is an alias for `test` to make the 3-tier naming (fast/smoke/full)
# explicit at the call site (see USK-728).
test-fast: test

# test-e2e-smoke is the merge-gate tier: M46 harness scenarios (USK-722–USK-727)
# plus a representative subset of connector / layer e2e tests covering each
# critical protocol path. The `e2e_smoke` build tag is an EXCLUSION filter:
# files marked `//go:build e2e && !e2e_smoke` are excluded from the smoke
# tier (they run only under `make test-e2e`). Files in the smoke tier keep
# the plain `//go:build e2e` constraint.
test-e2e-smoke: ensure-ui
	go test -race -v -timeout 10m -tags 'e2e e2e_smoke' ./...

# test-e2e is the full tier: every test guarded by `//go:build e2e` (smoke
# files included). Run nightly via the `nightly-e2e.yml` workflow; not part
# of the per-PR gate.
#
# GODEBUG=http2xconnect=1 enables RFC 8441 extended CONNECT in the
# golang.org/x/net/http2 transport AND server (read at package init).
# Required by the wss-over-h2 e2e tests (USK-781 in connector,
# TestE2E_ConnectModes_WSSOverH2_Full in mcptest); the proxy itself uses
# its own HTTP/2 layer and does not need this flag.
test-e2e: ensure-ui
	GODEBUG=http2xconnect=1 go test -race -v -timeout 30m -tags e2e ./...

test-cover: ensure-ui
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

vet: ensure-ui
	go vet ./...

fmt:
	gofmt -w .

# lint = the Go toolchain's own gofmt over the whole tree, plus golangci-lint for
# govet / staticcheck / unused / ineffassign / gocyclo (see .golangci.yml for why
# gofmt is deliberately NOT delegated to golangci-lint).
lint: ensure-ui
	@echo "==> gofmt check"
	@test -z "$$(gofmt -l .)" || (echo "Files not formatted:" && gofmt -l . && exit 1)
	@raw=$$(cat .golangci-lint-version 2>/dev/null); \
	 lines=$$(printf '%s\n' "$$raw" | grep -c ''); \
	 if [ "$$lines" -ne 1 ] || ! printf '%s' "$$raw" | grep -Eq '^v[0-9]+\.[0-9]+(\.[0-9]+)?$$'; then \
		echo ".golangci-lint-version must hold exactly one version tag, e.g. v2.13.2."; \
		if [ ! -f .golangci-lint-version ]; then \
			echo "  -> the file is missing."; \
		elif [ -z "$$raw" ]; then \
			echo "  -> the file is empty."; \
		elif [ "$$lines" -ne 1 ]; then \
			echo "  -> it holds $$lines lines; expected exactly one."; \
		elif printf '%s' "$$raw" | tr -d '\r' | grep -Eq '^v[0-9]+\.[0-9]+(\.[0-9]+)?$$'; then \
			echo "  -> it has CRLF line endings; re-check it out with LF (.gitattributes pins this)."; \
		else \
			echo "  -> got: $$raw"; \
		fi; \
		echo "golangci-lint-action's version-file input enforces the same vX.Y[.Z] shape in CI,"; \
		echo "though it trims surrounding whitespace first, so this check is the stricter of the two."; \
		exit 1; \
	 fi
	@pinned='$(GOLANGCI_LINT_VERSION)'; bad=0; \
	 if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "golangci-lint not found on PATH."; \
		bad=1; \
	 else \
		have="v$$(golangci-lint version --short)"; \
		if [ "$$have" != "$$pinned" ]; then \
			echo "golangci-lint version mismatch: have $$have, pinned $$pinned."; \
			echo "Local results can diverge from CI."; \
			bad=1; \
		fi; \
	 fi; \
	 if [ "$$bad" -eq 1 ]; then \
		echo "Install the pinned version -- do NOT use 'go install ...@latest':"; \
		echo "golangci-lint $$pinned declares 'go 1.26.0', so building it from source"; \
		echo "needs go1.26+, which is exactly the breakage USK-1043 removes."; \
		echo ""; \
		echo "  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$$pinned/install.sh \\"; \
		echo "    | sh -s -- -b $$(go env GOPATH)/bin $$pinned"; \
		exit 1; \
	 fi
	@echo "==> golangci-lint $(GOLANGCI_LINT_VERSION)"
	golangci-lint run

bench: ensure-ui
	go test -bench=. -benchmem -run=^$$ ./...

bench-compare:
	@echo "Usage: run benchmarks before and after changes, then compare with benchstat."
	@echo ""
	@echo "  make bench > old.txt"
	@echo "  # ... apply changes ..."
	@echo "  make bench > new.txt"
	@echo "  benchstat old.txt new.txt"
	@echo ""
	@echo "Install benchstat: go install golang.org/x/perf/cmd/benchstat@latest"

clean:
	rm -rf $(BINDIR) coverage.out coverage.html
