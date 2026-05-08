package mcptest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
)

// GRPCHitCounter records how many gRPC method invocations the upstream
// test server actually received. Tests use it as the durable
// SafetyFilter / Intercept assertion: when a pipeline step drops or
// blocks an envelope, the upstream handler never runs so the counter
// does not advance.
//
// Concurrency: increments happen on grpc-go server goroutines; reads
// happen on the test goroutine. Total / PerMethod use atomic loads.
type GRPCHitCounter struct {
	total atomic.Int64

	mu      sync.Mutex
	methods map[string]int64
}

// NewGRPCHitCounter constructs an empty counter. Exported for tests
// that want to share a counter across multiple upstreams.
func NewGRPCHitCounter() *GRPCHitCounter {
	return &GRPCHitCounter{methods: make(map[string]int64)}
}

// Total returns the cumulative number of upstream invocations recorded
// by the harness gRPC handler.
func (c *GRPCHitCounter) Total() int64 {
	if c == nil {
		return 0
	}
	return c.total.Load()
}

// PerMethod returns the number of invocations for the given fully-
// qualified gRPC method name (e.g. "/svc/Method"). Zero if the method
// has not been called.
func (c *GRPCHitCounter) PerMethod(fullMethod string) int64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.methods[fullMethod]
}

// record is invoked from inside the gRPC stream handler.
func (c *GRPCHitCounter) record(fullMethod string) {
	if c == nil {
		return
	}
	c.total.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.methods[fullMethod]++
}

// grpcRawCodecName is the name registered with grpc-go's encoding
// registry for the raw-bytes codec used by harness gRPC upstreams.
// Naming is deliberately scoped to mcptest so it does not collide with
// the homonymous codec inside internal/layer/grpc/grpc_integration_test.go
// (that package's codec lives in a different test binary).
const grpcRawCodecName = "mcptest-raw"

// grpcRawCodec round-trips *[]byte payloads without protobuf marshaling.
// The harness only needs to observe the raw bytes — it never decodes a
// schema — so this matches the hand-rolled-service pattern from
// internal/layer/grpc/grpc_integration_test.go.
type grpcRawCodec struct{}

func (grpcRawCodec) Name() string { return grpcRawCodecName }

func (grpcRawCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.(*[]byte)
	if !ok {
		return nil, fmt.Errorf("mcptest grpcRawCodec: Marshal: want *[]byte, got %T", v)
	}
	if b == nil {
		return nil, nil
	}
	out := make([]byte, len(*b))
	copy(out, *b)
	return out, nil
}

func (grpcRawCodec) Unmarshal(data []byte, v any) error {
	b, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("mcptest grpcRawCodec: Unmarshal: want *[]byte, got %T", v)
	}
	*b = make([]byte, len(data))
	copy(*b, data)
	return nil
}

func init() {
	encoding.RegisterCodec(grpcRawCodec{})
}

// GRPCSafetyServiceName is the fully-qualified gRPC service name
// registered on the harness gRPC upstream. Tests that drive a gRPC
// unary call via the proxy must address methods under this service —
// see GRPCSafetyEchoMethod for the canonical "/svc/method" string.
const (
	GRPCSafetyServiceName = "yorishiro.test.Safety"
	GRPCSafetyEchoMethod  = "/" + GRPCSafetyServiceName + "/Echo"
)

// grpcSafetyServiceDesc registers a single unary "Echo" method that
// echoes its raw []byte request back. We register a real grpc.ServiceDesc
// (rather than using grpc.UnknownServiceHandler) so the upstream takes
// the regular method-dispatch path that the proxy's grpclayer is built
// against — UnknownServiceHandler triggered an immediate RST_STREAM
// CANCEL through the proxy with no observable error on the upstream
// side, while the registered-service path goes through cleanly.
var grpcSafetyServiceDesc = grpc.ServiceDesc{
	ServiceName: GRPCSafetyServiceName,
	HandlerType: (*any)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Echo",
			Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				var req []byte
				if err := dec(&req); err != nil {
					return nil, err
				}
				h, _ := srv.(*grpcSafetyHandler)
				if h == nil || h.hits == nil {
					return nil, fmt.Errorf("mcptest grpc upstream: handler not configured")
				}
				h.hits.record(GRPCSafetyEchoMethod)
				resp := append([]byte(nil), req...)
				return &resp, nil
			},
		},
	},
	Metadata: GRPCSafetyServiceName,
}

// grpcSafetyHandler is the concrete service installed against
// grpcSafetyServiceDesc — the only state it carries is the hit counter
// the test asserts against.
type grpcSafetyHandler struct {
	hits *GRPCHitCounter
}

// buildGRPCUpstream stands up a *grpc.Server bound to a TLS listener
// (NextProtos=h2) using a freshly-minted self-signed leaf certificate
// for 127.0.0.1 / localhost.
//
// httptest's ServeHTTP+EnableHTTP2 path is unsuitable for hosting gRPC:
// grpc-go's handler-server transport interacts poorly with the http.Server
// SETTINGS frame, surfacing as `header list size to send violates the
// maximum size (0 bytes) set by server` on the first call. The canonical
// pattern is therefore net.Listen + tls.NewListener + grpc.Server.Serve;
// see internal/layer/grpc/grpc_integration_test.go::startGRPCUpstream
// for the reference.
//
// We still return a *httptest.Server-shaped value so the rest of the
// harness (UpstreamTLS field + cleanup path) does not need to fork by
// upstream protocol. The shell carries the URL and a Listener whose
// Close shuts down the gRPC server.
func buildGRPCUpstream() (*httptest.Server, *FingerprintObserver, *GRPCHitCounter, error) {
	leafCert, err := newSelfSignedLeaf("localhost", "127.0.0.1")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("self-signed leaf: %w", err)
	}
	base := &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}
	tlsCfg, fpObs := installFingerprintObserver(base)

	hits := NewGRPCHitCounter()
	gs := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.ForceServerCodec(grpcRawCodec{}),
	)
	gs.RegisterService(&grpcSafetyServiceDesc, &grpcSafetyHandler{hits: hits})

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("listen: %w", err)
	}

	wrapped := &grpcListener{Listener: tcpLn, gs: gs}
	wrapped.serveDone.Add(1)
	go func() {
		defer wrapped.serveDone.Done()
		// gs.Serve internally wraps the listener with TLS via the
		// credentials passed to NewServer, so we feed it the raw TCP
		// listener — not a tls.NewListener — to avoid double-wrapping.
		_ = gs.Serve(tcpLn)
	}()

	// Build a *httptest.Server shell. We do not call any of httptest's
	// start methods (NewUnstartedServer / StartTLS); those would spin
	// up an http.Server we do not want and allocate a duplicate
	// listener. The fields URL/Listener/Config/TLS are sufficient for
	// the harness, which only reads URL and calls Close.
	srv := &httptest.Server{
		Listener: wrapped,
		// Config must be non-nil because httptest.Server.Close calls
		// s.Config.SetKeepAlivesEnabled. An empty http.Server is a
		// safe no-op recipient.
		Config: &http.Server{},
		URL:    "https://" + tcpLn.Addr().String(),
		TLS:    tlsCfg,
	}
	return srv, fpObs, hits, nil
}

// grpcListener is the listener handed to httptest.Server. The harness
// cleanup path calls s.Listener.Close, so grpcListener.Close drains
// the gRPC server gracefully, releases the TCP listener, and waits for
// gs.Serve to exit before returning. Using sync.Once keeps Close safe
// to call multiple times (httptest.Server.Close + t.Cleanup
// double-firing).
type grpcListener struct {
	net.Listener
	gs        *grpc.Server
	serveDone sync.WaitGroup
	once      sync.Once
}

func (l *grpcListener) Close() error {
	var closeErr error
	l.once.Do(func() {
		// GracefulStop blocks until in-flight RPCs finish AND closes
		// the listener internally, after which gs.Serve returns.
		// Bound the wait so a hung RPC cannot deadlock test cleanup.
		done := make(chan struct{})
		go func() {
			l.gs.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			l.gs.Stop() // forceful — drops any leftover streams
			<-done
		}
		// gs.GracefulStop already closed the underlying TCP listener.
		// Calling Close again returns ErrClosed which we swallow as
		// idempotent teardown.
		_ = l.Listener.Close()
		l.serveDone.Wait()
	})
	return closeErr
}

// newSelfSignedLeaf mints an ECDSA P-256 self-signed leaf cert valid
// for the given hostnames, suitable for an in-process test TLS server.
// The cert is short-lived (1h) since it lives only for the duration of
// the test process.
func newSelfSignedLeaf(dnsNames ...string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "mcptest-grpc-upstream"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range dnsNames {
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, name)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        nil,
	}, nil
}
