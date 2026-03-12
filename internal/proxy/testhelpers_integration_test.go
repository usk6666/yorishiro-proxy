//go:build e2e

package proxy_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// pollFlows polls the store until the expected number of flows appear or timeout.
func pollFlows(t *testing.T, ctx context.Context, store flow.Store, opts flow.ListOptions, wantCount int) []*flow.Flow {
	t.Helper()
	var flows []*flow.Flow
	var err error
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListFlows(ctx, opts)
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) >= wantCount {
			return flows
		}
	}
	t.Fatalf("expected %d flows, got %d after polling", wantCount, len(flows))
	return nil
}

// getFlowMessages retrieves send and receive messages for a flow.
func getFlowMessages(t *testing.T, ctx context.Context, store flow.Store, flowID string) (send, recv *flow.Message) {
	t.Helper()
	msgs, err := store.GetMessages(ctx, flowID, flow.MessageListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	for _, m := range msgs {
		switch m.Direction {
		case "send":
			if send == nil {
				send = m
			}
		case "receive":
			if recv == nil {
				recv = m
			}
		}
	}
	return send, recv
}

// mustParseURL parses a URL string or panics.
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(fmt.Sprintf("mustParseURL(%q): %v", rawURL, err))
	}
	return u
}
