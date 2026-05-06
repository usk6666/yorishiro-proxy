BINARY := yorishiro-proxy
BINDIR := bin
MODULE := github.com/usk6666/yorishiro-proxy
DIST_DIR := internal/mcp/webui/dist

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

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
test-e2e: ensure-ui
	go test -race -v -timeout 30m -tags e2e ./...

test-cover: ensure-ui
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

vet: ensure-ui
	go vet ./...

fmt:
	gofmt -w .

lint: ensure-ui
	@echo "==> gofmt check"
	@test -z "$$(gofmt -l .)" || (echo "Files not formatted:" && gofmt -l . && exit 1)
	@echo "==> go vet"
	go vet ./...
	@echo "==> staticcheck"
	staticcheck ./...
	@echo "==> ineffassign"
	ineffassign ./...
	@echo "==> gocyclo (threshold: 15)"
	@test -z "$$(gocyclo -over 15 -ignore '_test\.go$$' .)" || (gocyclo -over 15 -ignore '_test\.go$$' . && exit 1)

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
