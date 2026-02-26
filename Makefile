BINARY := katashiro-proxy
BINDIR := bin
MODULE := github.com/usk6666/katashiro-proxy

.PHONY: build test test-cover vet clean

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
