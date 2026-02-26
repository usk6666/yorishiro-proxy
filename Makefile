BINARY := katashiro-proxy
BINDIR := bin
MODULE := github.com/usk6666/katashiro-proxy

.PHONY: build test test-cover vet clean worktree-clean

build: vet
	go build -o $(BINDIR)/$(BINARY) ./cmd/katashiro-proxy

test:
	go test -race -v ./...

test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

vet:
	go vet ./...

clean:
	rm -rf $(BINDIR) coverage.out coverage.html

worktree-clean:
	@echo "Removing stale worktrees..."
	@for dir in .claude/worktrees/agent-*; do \
		if [ -d "$$dir" ]; then \
			git worktree remove "$$dir" --force 2>/dev/null \
				&& echo "  removed: $$dir" || echo "  skip: $$dir"; \
		fi \
	done
	@git worktree prune
	@echo "Done. Remaining worktrees:"
	@git worktree list
