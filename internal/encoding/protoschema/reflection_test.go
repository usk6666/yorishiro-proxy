package protoschema

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	v1 "google.golang.org/grpc/reflection/grpc_reflection_v1"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// installFakeDial replaces the package-level reflectionDial seam with
// the supplied factory. The previous value is restored on test cleanup.
// Tests using t.Parallel must NOT use installFakeDial — the package
// seam is shared. (None of our tests run in parallel.)
func installFakeDial(t *testing.T, factory func(service string) reflectionStreamChannel) {
	t.Helper()
	orig := reflectionDial
	reflectionDial = func(_ context.Context, _ DiscoverOptions, service string) (reflectionStreamChannel, func(), error) {
		ch := factory(service)
		return ch, func() {}, nil
	}
	t.Cleanup(func() { reflectionDial = orig })
}

// fakeReflectionServer is a synthetic gRPC reflection server that
// services ServerReflectionInfo by reading marshaled requests from its
// input queue and crafting responses according to its configured state.
//
// Behaviour modes:
//   - mode="ok" — emit ListServicesResponse with services then
//     FileDescriptorResponse per FileContainingSymbol.
//   - mode="unimplemented-v1" — return GRPCEnd with status=12 on the
//     first read. v1alpha service path responds normally.
//   - mode="unimplemented-both" — always return status=12 on the first
//     read.
//   - mode="zero-services" — empty ListServicesResponse.
//   - mode="error-on-file" — ListServices succeeds; first
//     FileContainingSymbol returns an ErrorResponse.
//   - mode="slow" — block forever on the first request to exercise ctx
//     timeout behaviour.
type fakeReflectionServer struct {
	mode         string
	services     []string            // emitted by ListServices
	files        map[string][][]byte // per-service file_descriptor_proto bytes
	respondStart bool                // whether to push a synthetic GRPCStart envelope before Data
	t            *testing.T
}

// fakeServerChannel implements reflectionStreamChannel by routing
// requests through the configured fakeReflectionServer.
type fakeServerChannel struct {
	srv        *fakeReflectionServer
	service    string               // reflection service the client dialed
	sent       []*envelope.Envelope // captured Send-side envelopes
	pending    []*envelope.Envelope // queued response envelopes for Next to drain
	requestIdx int                  // tracks per-request response routing
}

func (c *fakeServerChannel) Send(_ context.Context, env *envelope.Envelope) error {
	c.sent = append(c.sent, env)
	c.handleSent(env)
	return nil
}

func (c *fakeServerChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	if len(c.pending) == 0 {
		if c.srv.mode == "slow" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		// No pending envelopes and no more Sends will arrive — return
		// EOF so the read loop surfaces a clear error.
		return nil, errors.New("fakeServerChannel: no envelopes to deliver")
	}
	env := c.pending[0]
	c.pending = c.pending[1:]
	return env, nil
}

// handleSent inspects each Send and queues the matching response shape
// per the configured server mode.
func (c *fakeServerChannel) handleSent(env *envelope.Envelope) {
	switch m := env.Message.(type) {
	case *envelope.GRPCStartMessage:
		// Start envelope from the client — no response yet.
		_ = m
	case *envelope.GRPCDataMessage:
		c.handleDataSend(m)
	case *envelope.GRPCEndMessage:
		// Close-send sentinel — no response.
	}
}

func (c *fakeServerChannel) handleDataSend(m *envelope.GRPCDataMessage) {
	// Pure end-marker (Payload==nil + WireLength==0 + EndStream=true):
	// matches CloseSend — no further response expected.
	if m.Payload == nil && m.WireLength == 0 && m.EndStream {
		return
	}

	c.requestIdx++

	// Mode shortcuts.
	switch c.srv.mode {
	case "unimplemented-both":
		c.queueUnimplementedEnd()
		return
	case "unimplemented-v1":
		if c.service == ReflectionV1Service {
			c.queueUnimplementedEnd()
			return
		}
		// v1alpha service path falls through to the happy path.
	case "slow":
		return // Next() will park on ctx
	}

	req := &v1.ServerReflectionRequest{}
	if err := proto.Unmarshal(m.Payload, req); err != nil {
		c.queueErrorData(13, "invalid request: "+err.Error())
		return
	}
	switch mr := req.MessageRequest.(type) {
	case *v1.ServerReflectionRequest_ListServices:
		c.handleListServices()
	case *v1.ServerReflectionRequest_FileContainingSymbol:
		c.handleFileContaining(mr.FileContainingSymbol)
	default:
		c.queueErrorData(13, "unsupported request type")
	}
}

func (c *fakeServerChannel) handleListServices() {
	if c.srv.mode == "zero-services" {
		c.queueListServices(nil)
		return
	}
	c.queueListServices(c.srv.services)
}

func (c *fakeServerChannel) handleFileContaining(svc string) {
	if c.srv.mode == "error-on-file" {
		c.queueErrorData(5, "file not found for symbol "+svc)
		return
	}
	files, ok := c.srv.files[svc]
	if !ok {
		c.queueErrorData(5, "unknown symbol "+svc)
		return
	}
	c.queueFileDescriptor(files)
}

func (c *fakeServerChannel) queueListServices(services []string) {
	respSvcs := make([]*v1.ServiceResponse, 0, len(services))
	for _, s := range services {
		respSvcs = append(respSvcs, &v1.ServiceResponse{Name: s})
	}
	resp := &v1.ServerReflectionResponse{
		MessageResponse: &v1.ServerReflectionResponse_ListServicesResponse{
			ListServicesResponse: &v1.ListServiceResponse{Service: respSvcs},
		},
	}
	c.queueDataResponse(resp)
}

func (c *fakeServerChannel) queueFileDescriptor(files [][]byte) {
	resp := &v1.ServerReflectionResponse{
		MessageResponse: &v1.ServerReflectionResponse_FileDescriptorResponse{
			FileDescriptorResponse: &v1.FileDescriptorResponse{FileDescriptorProto: files},
		},
	}
	c.queueDataResponse(resp)
}

func (c *fakeServerChannel) queueErrorData(code int32, msg string) {
	resp := &v1.ServerReflectionResponse{
		MessageResponse: &v1.ServerReflectionResponse_ErrorResponse{
			ErrorResponse: &v1.ErrorResponse{ErrorCode: code, ErrorMessage: msg},
		},
	}
	c.queueDataResponse(resp)
}

func (c *fakeServerChannel) queueDataResponse(resp *v1.ServerReflectionResponse) {
	payload, err := proto.Marshal(resp)
	if err != nil {
		c.srv.t.Fatalf("marshal response: %v", err)
	}
	if c.srv.respondStart && c.requestIdx == 1 {
		c.pending = append(c.pending, &envelope.Envelope{
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolGRPC,
			Message: &envelope.GRPCStartMessage{
				Service:     c.service,
				Method:      ReflectionMethod,
				ContentType: "application/grpc+proto",
			},
		})
	}
	c.pending = append(c.pending, &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCDataMessage{
			WireLength: uint32(len(payload)),
			Payload:    payload,
		},
	})
}

func (c *fakeServerChannel) queueUnimplementedEnd() {
	c.pending = append(c.pending, &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCEndMessage{
			Status:  grpcStatusUnimplemented,
			Message: "method ServerReflectionInfo not implemented",
		},
	})
}

// newReflectionDialAdapter returns a reflectionDial factory bound to srv.
func newReflectionDialAdapter(srv *fakeReflectionServer) func(service string) reflectionStreamChannel {
	return func(service string) reflectionStreamChannel {
		return &fakeServerChannel{srv: srv, service: service}
	}
}

// buildTestFileDescriptorProto returns a marshaled FileDescriptorProto
// describing a single service+method. The resulting bytes can be fed
// back into a FileDescriptorResponse to drive the fake server.
func buildTestFileDescriptorProto(t *testing.T, packageName, fileName, serviceName, methodName, inputMsg, outputMsg string) []byte {
	t.Helper()
	syntax := "proto3"
	fd := &descriptorpb.FileDescriptorProto{
		Name:    &fileName,
		Package: &packageName,
		Syntax:  &syntax,
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name:  &inputMsg,
				Field: []*descriptorpb.FieldDescriptorProto{},
			},
			{
				Name:  &outputMsg,
				Field: []*descriptorpb.FieldDescriptorProto{},
			},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: &serviceName,
				Method: []*descriptorpb.MethodDescriptorProto{
					{
						Name:       &methodName,
						InputType:  strPtr("." + packageName + "." + inputMsg),
						OutputType: strPtr("." + packageName + "." + outputMsg),
					},
				},
			},
		},
	}
	raw, err := proto.Marshal(fd)
	if err != nil {
		t.Fatalf("marshal FileDescriptorProto: %v", err)
	}
	return raw
}

func strPtr(s string) *string { return &s }

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

func TestDiscover_HappyPath_V1(t *testing.T) {
	greeterFD := buildTestFileDescriptorProto(t, "demo", "demo/greeter.proto", "Greeter", "SayHello", "HelloRequest", "HelloResponse")
	srv := &fakeReflectionServer{
		mode:     "ok",
		services: []string{"demo.Greeter"},
		files: map[string][][]byte{
			"demo.Greeter": {greeterFD},
		},
		t: t,
	}
	installFakeDial(t, newReflectionDialAdapter(srv))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := Discover(ctx, DiscoverOptions{
		TargetAddr: "127.0.0.1:9000",
		Scheme:     "http",
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res.ReflectionVersion != "v1" {
		t.Errorf("ReflectionVersion = %q, want v1", res.ReflectionVersion)
	}
	if len(res.Services) != 1 || res.Services[0].Service != "demo.Greeter" {
		t.Fatalf("Services = %+v, want [demo.Greeter]", res.Services)
	}
	if len(res.Services[0].Methods) != 1 || res.Services[0].Methods[0].Name != "SayHello" {
		t.Errorf("Methods = %+v, want [SayHello]", res.Services[0].Methods)
	}
	if len(res.AssembledRawDescriptorSet) == 0 {
		t.Errorf("AssembledRawDescriptorSet is empty")
	}
}

func TestDiscover_V1AlphaFallback(t *testing.T) {
	greeterFD := buildTestFileDescriptorProto(t, "demo", "demo/greeter.proto", "Greeter", "SayHello", "HelloRequest", "HelloResponse")
	srv := &fakeReflectionServer{
		mode:     "unimplemented-v1",
		services: []string{"demo.Greeter"},
		files: map[string][][]byte{
			"demo.Greeter": {greeterFD},
		},
		t: t,
	}
	installFakeDial(t, newReflectionDialAdapter(srv))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := Discover(ctx, DiscoverOptions{
		TargetAddr: "127.0.0.1:9000",
		Scheme:     "http",
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res.ReflectionVersion != "v1alpha" {
		t.Errorf("ReflectionVersion = %q, want v1alpha", res.ReflectionVersion)
	}
}

func TestDiscover_BothUnimplemented(t *testing.T) {
	srv := &fakeReflectionServer{mode: "unimplemented-both", t: t}
	installFakeDial(t, newReflectionDialAdapter(srv))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Discover(ctx, DiscoverOptions{
		TargetAddr: "127.0.0.1:9000",
		Scheme:     "http",
	})
	if err == nil {
		t.Fatal("expected error when both reflection versions return UNIMPLEMENTED")
	}
	msg := err.Error()
	if !strings.Contains(msg, "does not implement gRPC reflection") {
		t.Errorf("error must mention reflection not implemented: %q", msg)
	}
	if !strings.Contains(msg, "reflection.Register(s)") {
		t.Errorf("error must include enable-reflection hint: %q", msg)
	}
	if !strings.Contains(msg, "github.com/grpc/grpc") {
		t.Errorf("error must include upstream spec link: %q", msg)
	}
}

func TestDiscover_ZeroServices(t *testing.T) {
	srv := &fakeReflectionServer{
		mode:     "zero-services",
		services: nil,
		t:        t,
	}
	installFakeDial(t, newReflectionDialAdapter(srv))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Discover(ctx, DiscoverOptions{
		TargetAddr: "127.0.0.1:9000",
		Scheme:     "http",
	})
	if err == nil {
		t.Fatal("expected error when target reports zero services")
	}
	if !strings.Contains(err.Error(), "reflection registry is empty") {
		t.Errorf("error must mention empty registry: %q", err.Error())
	}
}

func TestDiscover_PartialFailureAborts(t *testing.T) {
	srv := &fakeReflectionServer{
		mode:     "error-on-file",
		services: []string{"demo.Greeter"},
		t:        t,
	}
	installFakeDial(t, newReflectionDialAdapter(srv))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Discover(ctx, DiscoverOptions{
		TargetAddr: "127.0.0.1:9000",
		Scheme:     "http",
	})
	if err == nil {
		t.Fatal("expected error when FileContainingSymbol fails after ListServices")
	}
	if !strings.Contains(err.Error(), "FileContainingSymbol") {
		t.Errorf("error must mention the failing step: %q", err.Error())
	}
}

func TestDiscover_ServiceFilter_FilterMiss(t *testing.T) {
	greeterFD := buildTestFileDescriptorProto(t, "demo", "demo/greeter.proto", "Greeter", "SayHello", "HelloRequest", "HelloResponse")
	srv := &fakeReflectionServer{
		mode:     "ok",
		services: []string{"demo.Greeter"},
		files: map[string][][]byte{
			"demo.Greeter": {greeterFD},
		},
		t: t,
	}
	installFakeDial(t, newReflectionDialAdapter(srv))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Discover(ctx, DiscoverOptions{
		TargetAddr:    "127.0.0.1:9000",
		Scheme:        "http",
		ServiceFilter: []string{"demo.Missing"},
	})
	if err == nil {
		t.Fatal("expected error when filter mentions a service not present")
	}
	if !strings.Contains(err.Error(), "demo.Missing") {
		t.Errorf("error must mention the missing service: %q", err.Error())
	}
}

func TestDiscover_ServiceFilter_HappyPath(t *testing.T) {
	greeterFD := buildTestFileDescriptorProto(t, "demo", "demo/greeter.proto", "Greeter", "SayHello", "HelloRequest", "HelloResponse")
	echoFD := buildTestFileDescriptorProto(t, "demo", "demo/echo.proto", "Echo", "Ping", "PingRequest", "PingResponse")
	srv := &fakeReflectionServer{
		mode:     "ok",
		services: []string{"demo.Greeter", "demo.Echo"},
		files: map[string][][]byte{
			"demo.Greeter": {greeterFD},
			"demo.Echo":    {echoFD},
		},
		t: t,
	}
	installFakeDial(t, newReflectionDialAdapter(srv))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := Discover(ctx, DiscoverOptions{
		TargetAddr:    "127.0.0.1:9000",
		Scheme:        "http",
		ServiceFilter: []string{"demo.Greeter"},
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Services) != 1 || res.Services[0].Service != "demo.Greeter" {
		t.Errorf("Services = %+v, want only demo.Greeter", res.Services)
	}
}

func TestDiscover_StripsReflectionServices(t *testing.T) {
	greeterFD := buildTestFileDescriptorProto(t, "demo", "demo/greeter.proto", "Greeter", "SayHello", "HelloRequest", "HelloResponse")
	srv := &fakeReflectionServer{
		mode: "ok",
		services: []string{
			"demo.Greeter",
			ReflectionV1Service,
			ReflectionV1AlphaService,
		},
		files: map[string][][]byte{
			"demo.Greeter": {greeterFD},
		},
		t: t,
	}
	installFakeDial(t, newReflectionDialAdapter(srv))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := Discover(ctx, DiscoverOptions{
		TargetAddr: "127.0.0.1:9000",
		Scheme:     "http",
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, spec := range res.Services {
		if spec.Service == ReflectionV1Service || spec.Service == ReflectionV1AlphaService {
			t.Errorf("reflection-own service leaked into result: %q", spec.Service)
		}
	}
	if len(res.Services) != 1 || res.Services[0].Service != "demo.Greeter" {
		t.Errorf("Services = %+v, want only demo.Greeter", res.Services)
	}
}

func TestDiscover_AssembledSetSizeCap(t *testing.T) {
	// Build enough large FileDescriptorProto entries so the marshaled
	// FileDescriptorSet exceeds MaxDescriptorSetBytes (16 MiB). Each
	// generated FD is ~700 KiB; 25 of them produce >17 MiB.
	files := make([][]byte, 0, 25)
	for i := 0; i < 25; i++ {
		// Distinct filenames so dedup doesn't collapse them.
		fd := buildLargeFileDescriptorProto(t, "demo", "demo/large_"+itoa(i)+".proto", "BigService"+itoa(i), "DoIt")
		files = append(files, fd)
	}
	_, err := assembleFileDescriptorSet(files)
	if err == nil {
		t.Fatal("expected size-cap error when assembled set exceeds MaxDescriptorSetBytes")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("error must mention size cap: %q", err.Error())
	}
}

// buildLargeFileDescriptorProto creates a FileDescriptorProto with one
// message carrying a SourceCodeInfo Location with a very long
// leading_comments payload. Comments are valid metadata for protodesc
// and are preserved by proto.Marshal, so the resulting bytes inflate
// without requiring thousands of distinct fields. Cheaper to build and
// marshal than the fields-per-message approach.
func buildLargeFileDescriptorProto(t *testing.T, packageName, fileName, serviceName, methodName string) []byte {
	t.Helper()
	const padBytes = 700_000 // ~700 KiB per file; 24 files > 16 MiB total
	syntax := "proto3"
	in := "BigRequest"
	out := "BigResponse"
	// Build one big leading_comments string. Build once per call —
	// reusing the same []byte across builds would mutate-share.
	big := make([]byte, padBytes)
	for i := range big {
		big[i] = 'x'
	}
	pad := string(big)
	leadingPath := []int32{}
	fd := &descriptorpb.FileDescriptorProto{
		Name:    &fileName,
		Package: &packageName,
		Syntax:  &syntax,
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: &in},
			{Name: &out},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: &serviceName,
				Method: []*descriptorpb.MethodDescriptorProto{
					{
						Name:       &methodName,
						InputType:  strPtr("." + packageName + "." + in),
						OutputType: strPtr("." + packageName + "." + out),
					},
				},
			},
		},
		SourceCodeInfo: &descriptorpb.SourceCodeInfo{
			Location: []*descriptorpb.SourceCodeInfo_Location{
				{
					Path:            leadingPath,
					LeadingComments: &pad,
				},
			},
		},
	}
	raw, err := proto.Marshal(fd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

func TestDiscover_DeduplicatesByFilename(t *testing.T) {
	// Two services share a common file (e.g. google/protobuf/empty.proto).
	// The assembled set must include each filename once.
	commonFD := buildTestFileDescriptorProto(t, "demo", "demo/common.proto", "Service1", "M1", "Req1", "Resp1")
	serviceAFD := buildTestFileDescriptorProto(t, "demo", "demo/a.proto", "ServiceA", "M", "ReqA", "RespA")
	srv := &fakeReflectionServer{
		mode:     "ok",
		services: []string{"demo.Service1", "demo.ServiceA"},
		files: map[string][][]byte{
			"demo.Service1": {commonFD},
			"demo.ServiceA": {serviceAFD, commonFD}, // common appears twice
		},
		t: t,
	}
	installFakeDial(t, newReflectionDialAdapter(srv))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := Discover(ctx, DiscoverOptions{
		TargetAddr: "127.0.0.1:9000",
		Scheme:     "http",
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	// Both Service1 and ServiceA must be present.
	if len(res.Services) != 2 {
		t.Errorf("Services len = %d, want 2", len(res.Services))
	}
	// The assembled FileDescriptorSet must include demo/common.proto only once.
	set := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(res.AssembledRawDescriptorSet, set); err != nil {
		t.Fatalf("unmarshal assembled: %v", err)
	}
	names := map[string]int{}
	for _, f := range set.File {
		names[f.GetName()]++
	}
	if names["demo/common.proto"] != 1 {
		t.Errorf("common file count = %d, want 1 (filenames: %+v)", names["demo/common.proto"], names)
	}
}

func TestDiscover_TargetAddrRequired(t *testing.T) {
	_, err := Discover(context.Background(), DiscoverOptions{})
	if err == nil {
		t.Fatal("expected error when target_addr is empty")
	}
	if !strings.Contains(err.Error(), "target_addr") {
		t.Errorf("error must mention target_addr: %q", err.Error())
	}
}

func TestDiscover_UnsupportedScheme(t *testing.T) {
	_, err := Discover(context.Background(), DiscoverOptions{
		TargetAddr: "127.0.0.1:9000",
		Scheme:     "ftp",
	})
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
	if !strings.Contains(err.Error(), "ftp") {
		t.Errorf("error must mention the bad scheme: %q", err.Error())
	}
}

func TestDiscover_HTTPSRequiresTransport(t *testing.T) {
	_, err := Discover(context.Background(), DiscoverOptions{
		TargetAddr: "127.0.0.1:9000",
		// Scheme defaults to https; no Transport supplied.
	})
	if err == nil {
		t.Fatal("expected error when https has no TLSTransport")
	}
	if !strings.Contains(err.Error(), "TLSTransport") {
		t.Errorf("error must mention TLSTransport: %q", err.Error())
	}
}

func TestAssembleFileDescriptorSet_DeduplicatesByFilename(t *testing.T) {
	fd := buildTestFileDescriptorProto(t, "demo", "demo/x.proto", "S", "M", "Req", "Resp")
	raw, err := assembleFileDescriptorSet([][]byte{fd, fd, fd})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	set := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(raw, set); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(set.File) != 1 {
		t.Errorf("File len = %d, want 1 (dedup by filename)", len(set.File))
	}
}

func TestAssembleFileDescriptorSet_RejectsEmpty(t *testing.T) {
	_, err := assembleFileDescriptorSet(nil)
	if err == nil {
		t.Fatal("expected error on empty input")
	}
}

func TestSelectCandidateServices_StripsReflection(t *testing.T) {
	out, err := selectCandidateServices(
		[]string{"demo.A", ReflectionV1Service, ReflectionV1AlphaService, "demo.B"},
		nil,
	)
	if err != nil {
		t.Fatalf("selectCandidateServices: %v", err)
	}
	if len(out) != 2 || out[0] != "demo.A" || out[1] != "demo.B" {
		t.Errorf("got %v, want [demo.A demo.B]", out)
	}
}

func TestSelectCandidateServices_FilterMissError(t *testing.T) {
	_, err := selectCandidateServices(
		[]string{"demo.A"},
		[]string{"demo.B"},
	)
	if err == nil {
		t.Fatal("expected error on filter miss")
	}
}

func TestIsUnimplementedErr(t *testing.T) {
	if !isUnimplementedErr(&reflectionRPCError{Code: grpcStatusUnimplemented}) {
		t.Error("isUnimplementedErr false negative")
	}
	if isUnimplementedErr(&reflectionRPCError{Code: 13}) {
		t.Error("isUnimplementedErr false positive on non-12 code")
	}
	if isUnimplementedErr(errors.New("plain")) {
		t.Error("isUnimplementedErr false positive on plain error")
	}
	if isUnimplementedErr(nil) {
		t.Error("isUnimplementedErr false positive on nil")
	}
}
