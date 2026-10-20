//go:build e2e && !e2e_smoke

package mcp

// resend_grpc_output_filter_integration_test.go — Output Filter coverage
// for the resend_grpc start_metadata / end.trailers return path
// (USK-1276). Reuses the raw codec and session helpers from
// resend_grpc_integration_test.go (same build tags).
//
// The upstream sets response header metadata and a trailer carrying
// email addresses. With an Output rule configured, resend_grpc must hand
// the agent a masked copy (name order and casing preserved, like query's
// filterOutputHeaderKVs), while the recorded flows keep the cleartext.

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

const (
	usk1276GRPCService = "yorishiro.test.OutputFilter"
	usk1276GRPCMethod  = "Unary"
)

type usk1276GRPCHandler interface{}

type usk1276GRPCServer struct{}

var usk1276GRPCServiceDesc = grpc.ServiceDesc{
	ServiceName: usk1276GRPCService,
	HandlerType: (*usk1276GRPCHandler)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: usk1276GRPCMethod,
			Handler: func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				var req []byte
				if err := dec(&req); err != nil {
					return nil, err
				}
				// Two values under one key: grpc-go emits a key's values
				// in slice order, whereas distinct keys come out in map
				// order — so duplicate values are the deterministic way
				// to observe order preservation.
				if err := grpc.SetHeader(ctx, metadata.Pairs(
					"x-contact", "alice@example.com",
					"x-contact", "nothing-here",
				)); err != nil {
					return nil, err
				}
				if err := grpc.SetTrailer(ctx, metadata.Pairs("x-owner", "bob@example.com")); err != nil {
					return nil, err
				}
				resp := []byte("ok")
				return &resp, nil
			},
		},
	},
	Metadata: usk1276GRPCService,
}

func startUSK1276GRPCUpstream(t *testing.T) string {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	leaf, err := cert.NewIssuer(ca).GetCertificate("localhost")
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	})
	gs := grpc.NewServer(grpc.Creds(creds), grpc.ForceServerCodec(resendGRPCRawCodec{}))
	gs.RegisterService(&usk1276GRPCServiceDesc, &usk1276GRPCServer{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(func() {
		gs.Stop()
		_ = ln.Close()
	})
	return ln.Addr().String()
}

func indexOfHeaderKV(list []headerKV, name string) int {
	for i, kv := range list {
		if kv.Name == name {
			return i
		}
	}
	return -1
}

// G1: start_metadata and end.trailers are masked in the returned copy;
// order is preserved; the recorded flows keep the cleartext.
func TestResendGRPC_OutputFilter_MasksMetadataAndTrailers(t *testing.T) {
	store := newTestStore(t)
	// Metadata / trailers are masked by header-target rules (the same
	// FilterOutputHeaders policy query applies to gRPC metadata). The
	// built-in email preset is body-target only, so declare the rule
	// with an explicit headers target.
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{
			{
				ID:          "mask-email",
				Pattern:     `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
				Targets:     []string{"headers"},
				Action:      "mask",
				Replacement: "[EMAIL]",
			},
		},
	})
	if err != nil {
		t.Fatalf("safety.NewEngine: %v", err)
	}
	ctx := context.Background()
	srv := newServer(ctx, nil, store, nil,
		WithSafetyEngine(engine),
		WithTLSTransport(&transport.StandardTransport{InsecureSkipVerify: true}),
	)
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := gomcp.NewClient(&gomcp.Implementation{Name: "usk1276-grpc", Version: "v0.0.1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	addr := startUSK1276GRPCUpstream(t)
	res := callResendGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     usk1276GRPCService,
		"method":      usk1276GRPCMethod,
		"messages":    []map[string]any{{"payload": "ping"}},
		"timeout_ms":  10000,
	})
	var result resendGRPCResult
	decodeResendGRPCResult(t, res, &result)

	// start_metadata: masked, order preserved.
	var contacts []string
	for _, kv := range result.StartMetadata {
		if kv.Name == "x-contact" {
			contacts = append(contacts, kv.Value)
		}
	}
	if len(contacts) != 2 {
		t.Fatalf("start_metadata x-contact values = %v, want 2 entries: %+v", contacts, result.StartMetadata)
	}
	if contacts[0] != "[EMAIL]" {
		t.Errorf("start_metadata x-contact[0] = %q, want %q", contacts[0], "[EMAIL]")
	}
	if contacts[1] != "nothing-here" {
		t.Errorf("start_metadata x-contact[1] = %q, want unchanged %q (order preserved)", contacts[1], "nothing-here")
	}

	// end.trailers: masked.
	if result.End == nil {
		t.Fatal("result.End is nil; expected trailers")
	}
	oi := indexOfHeaderKV(result.End.Trailers, "x-owner")
	if oi < 0 {
		t.Fatalf("end.trailers missing x-owner: %+v", result.End.Trailers)
	}
	if got := result.End.Trailers[oi].Value; got != "[EMAIL]" {
		t.Errorf("end.trailers x-owner = %q, want %q", got, "[EMAIL]")
	}

	// Recorded flows keep the cleartext (Principle 7).
	recv, err := store.GetFlows(ctx, result.StreamID, flow.FlowListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	var sawContact, sawOwner, sawMask bool
	for _, f := range recv {
		for _, vals := range f.Headers {
			for _, v := range vals {
				sawContact = sawContact || v == "alice@example.com"
				sawOwner = sawOwner || v == "bob@example.com"
				sawMask = sawMask || strings.Contains(v, "[EMAIL]")
			}
		}
		for _, vals := range f.Trailers {
			for _, v := range vals {
				sawOwner = sawOwner || v == "bob@example.com"
				sawMask = sawMask || strings.Contains(v, "[EMAIL]")
			}
		}
	}
	if !sawContact || !sawOwner {
		t.Errorf("recorded receive flows lost cleartext metadata: contact=%v owner=%v", sawContact, sawOwner)
	}
	if sawMask {
		t.Error("Output Filter mask leaked into recorded flows")
	}
}
