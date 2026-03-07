BINARY := yorishiro-proxy
BINDIR := bin
MODULE := github.com/usk6666/yorishiro-proxy
DIST_DIR := internal/mcp/webui/dist

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build build-ui ensure-ui dev-ui test test-e2e test-cover vet lint fmt clean bench bench-compare

build: build-ui vet
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(BINARY) ./cmd/yorishiro-proxy

build-ui:
	cd web && pnpm install --frozen-lockfile && pnpm run build

ensure-ui:
	@if [ ! -d $(DIST_DIR) ]; then $(MAKE) build-ui; fi

dev-ui:
	cd web && pnpm run dev

test: ensure-ui
	go test -race -v ./...

test-e2e: ensure-ui
	go test -race -v -tags e2e ./...

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
