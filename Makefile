BINARY := yorishiro-proxy
BINDIR := bin
MODULE := github.com/usk6666/yorishiro-proxy

.PHONY: build build-ui dev-ui test test-cover vet clean bench bench-compare

build: build-ui vet
	go build -o $(BINDIR)/$(BINARY) ./cmd/yorishiro-proxy

build-ui:
	cd web && pnpm install --frozen-lockfile && pnpm run build

dev-ui:
	cd web && pnpm run dev

test:
	go test -race -v ./...

test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

vet:
	go vet ./...

bench:
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
