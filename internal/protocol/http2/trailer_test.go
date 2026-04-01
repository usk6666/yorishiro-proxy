package http2

import (
	"context"
	"fmt"
	"io"
	gohttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestWriteResponseToClient_Trailers(t *testing.T) {
	// Upstream sends gRPC-style trailers.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(gohttp.StatusOK)
		w.Write([]byte("grpc-body"))
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Message", "OK")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	addr, cancel := startH2CProxyListener(t, handler, "test-trailer", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/grpc.Service/Method", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL, nil)
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	// Must read body fully before trailers are available.
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify trailers were forwarded to the client.
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Errorf("Grpc-Status trailer = %q, want %q", got, "0")
	}
	if got := resp.Trailer.Get("Grpc-Message"); got != "OK" {
		t.Errorf("Grpc-Message trailer = %q, want %q", got, "OK")
	}
}

func TestWriteResponseToClient_NoTrailers(t *testing.T) {
	// Upstream sends no trailers — should work as before.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Test", "no-trailer")
		w.WriteHeader(gohttp.StatusOK)
		w.Write([]byte("no-trailers"))
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	addr, cancel := startH2CProxyListener(t, handler, "test-no-trailer", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "no-trailers" {
		t.Errorf("body = %q, want %q", string(body), "no-trailers")
	}
}

func TestTrailers_OutputFilter_AppliedToTrailers(t *testing.T) {
	// Upstream sends a trailer containing sensitive data.
	// The output filter should mask it.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(gohttp.StatusOK)
		w.Write([]byte("body"))
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "2")
		// Include a credit card number pattern in the message.
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Message", "error: card 4111111111111111 invalid")
	}))
	defer upstream.Close()

	// Create a safety engine with an output rule that masks credit card numbers.
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{{
			ID:      "cc-mask",
			Name:    "credit card mask",
			Pattern: `\b4[0-9]{15}\b`,
			Targets: []string{"body", "headers"},
			Action:  "mask",
		}},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetSafetyEngine(engine)

	addr, cancel := startH2CProxyListener(t, handler, "test-trailer-filter", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/grpc.Service/Method", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL, nil)
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	grpcMsg := resp.Trailer.Get("Grpc-Message")
	// The credit card number should be masked.
	if grpcMsg == "error: card 4111111111111111 invalid" {
		t.Error("Grpc-Message trailer was not masked by output filter")
	}
	// Grpc-Status should be unchanged (not a credit card pattern).
	if got := resp.Trailer.Get("Grpc-Status"); got != "2" {
		t.Errorf("Grpc-Status trailer = %q, want %q", got, "2")
	}
}

func TestTrailers_PluginHook_ObservesAndModifiesTrailers(t *testing.T) {
	// Plugin reads trailers from the response and modifies them.
	script := writeStarlarkScript(t, "modify_trailers.star", `
def on_receive_from_server(data):
    trailers = list(data.get("trailers", []))
    trailers.append({"name": "x-plugin-trailer", "value": "added-by-plugin"})
    data["trailers"] = trailers
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		w.Write([]byte("body"))
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := setupPluginEngine(t, script, "h2", []string{"on_receive_from_server"})
	defer engine.Close()
	handler.SetPluginEngine(engine)

	addr, cancel := startH2CProxyListener(t, handler, "test-plugin-trailer", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/grpc.Service/Method", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL, nil)
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	// Verify original trailer is preserved.
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Errorf("Grpc-Status trailer = %q, want %q", got, "0")
	}

	// Verify plugin-added trailer.
	if got := resp.Trailer.Get("X-Plugin-Trailer"); got != "added-by-plugin" {
		t.Errorf("X-Plugin-Trailer = %q, want %q", got, "added-by-plugin")
	}
}
