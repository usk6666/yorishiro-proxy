package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/usk6666/katashiro-proxy/internal/config"
	"github.com/usk6666/katashiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/katashiro-proxy/internal/protocol/http"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg := config.Default()
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "proxy listen address")
	flag.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite database path")
	flag.Parse()

	// Initialize SQLite session store.
	store, err := session.NewSQLiteStore(ctx, cfg.DBPath)
	if err != nil {
		return fmt.Errorf("init session store: %w", err)
	}
	defer store.Close()

	// Build protocol handlers and detector.
	httpHandler := protohttp.NewHandler(store)
	detector := protocol.NewDetector(httpHandler)

	// Start TCP listener.
	listener := proxy.NewListener(cfg.ListenAddr, detector)
	fmt.Fprintf(os.Stderr, "katashiro-proxy: listening on %s (db: %s)\n", cfg.ListenAddr, cfg.DBPath)

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.Start(ctx)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "katashiro-proxy: shutting down...")
		return nil
	}
}
