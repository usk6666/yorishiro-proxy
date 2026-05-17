package protoschema

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// MaxDescriptorSetBytes is the maximum allowed base64-decoded size for a
// FileDescriptorSet payload. 16 MiB matches the design-review decision
// (Resolved #16): protoc-generated descriptor sets for normal services
// sit at <100 KiB; the 16 MiB ceiling is two orders of magnitude above
// realistic input while bounding memory exposure when an attacker supplies
// a pathological descriptor (CWE-770).
const MaxDescriptorSetBytes = 16 * 1024 * 1024

// MethodSpec describes a single RPC method's input/output types, used by
// the MCP grpc_schema list action and by the registry's lookup helpers.
type MethodSpec struct {
	// Name is the method's bare name (e.g. "SayHello").
	Name string
	// Input is the fully-qualified input type name (e.g. "pkg.Foo").
	Input string
	// Output is the fully-qualified output type name (e.g. "pkg.Bar").
	Output string
	// InputDesc is the resolved descriptor used for Decode/Encode on
	// the request side. Never nil for a successfully registered entry.
	InputDesc protoreflect.MessageDescriptor
	// OutputDesc is the resolved descriptor used for Decode/Encode on
	// the response side. Never nil for a successfully registered entry.
	OutputDesc protoreflect.MessageDescriptor
}

// ServiceSpec describes one registered service with its methods.
type ServiceSpec struct {
	// Service is the fully-qualified service name (e.g. "pkg.Greeter").
	Service string
	// Methods is the list of methods on the service, ordered by name.
	Methods []MethodSpec
	// SourceLabel is the caller-supplied label (filename hint or arbitrary
	// tag) for diagnostic display. Empty when not supplied.
	SourceLabel string
	// RegisteredAt is the wall-clock time the entry was added to the
	// registry. UTC.
	RegisteredAt time.Time
}

// Registry holds (service, method) → MessageDescriptor entries.
//
// The implementation uses atomic.Pointer[snapshot] for lock-free reads:
// every mutating call (Register / Unregister / Clear) builds a new
// snapshot map, then atomically swaps the pointer. Hot-path lookup is a
// single Load() + map read with no synchronisation cost. This is the
// design-review answer to Resolved #5 / U3.
type Registry struct {
	current atomic.Pointer[snapshot]
}

// snapshot is the immutable inner state swapped on every write.
type snapshot struct {
	// methods is keyed by "service/method" (the same key shape stored
	// in Flow.Metadata via grpc_service + grpc_method).
	methods map[string]*MethodSpec
	// services keys by fully-qualified service name. Used by list /
	// unregister and by overlay-on-register to remove existing entries
	// for a service before writing the new ones.
	services map[string]*ServiceSpec
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	r := &Registry{}
	r.current.Store(&snapshot{
		methods:  make(map[string]*MethodSpec),
		services: make(map[string]*ServiceSpec),
	})
	return r
}

// LookupMethod returns the MethodSpec for (service, method) or nil when
// no entry is registered. Lock-free.
func (r *Registry) LookupMethod(service, method string) *MethodSpec {
	if r == nil {
		return nil
	}
	s := r.current.Load()
	if s == nil {
		return nil
	}
	return s.methods[methodKey(service, method)]
}

// ListServices returns the registered services in alphabetical order.
// The returned slice is freshly allocated and safe for the caller to
// mutate.
func (r *Registry) ListServices() []*ServiceSpec {
	if r == nil {
		return nil
	}
	s := r.current.Load()
	if s == nil {
		return nil
	}
	out := make([]*ServiceSpec, 0, len(s.services))
	for _, svc := range s.services {
		out = append(out, svc)
	}
	sortServices(out)
	return out
}

// Register installs the given services into the registry. Last-write-wins
// semantics: any pre-existing entry for a service in the input list is
// fully replaced. Other services in the registry are untouched.
//
// The snapshot is built first; only the final atomic Store is observable
// by concurrent readers (Resolved #5).
func (r *Registry) Register(services []*ServiceSpec) {
	if r == nil || len(services) == 0 {
		return
	}
	old := r.current.Load()
	newMethods := make(map[string]*MethodSpec, len(old.methods))
	newServices := make(map[string]*ServiceSpec, len(old.services))
	// Carry over the unaffected entries (services not in the new list).
	skip := make(map[string]struct{}, len(services))
	for _, svc := range services {
		skip[svc.Service] = struct{}{}
	}
	for name, svc := range old.services {
		if _, drop := skip[name]; drop {
			continue
		}
		newServices[name] = svc
	}
	for key, m := range old.methods {
		// methodKey == "service/method"; the service prefix is in skip
		// when we are replacing it.
		i := strings.Index(key, "/")
		if i >= 0 {
			if _, drop := skip[key[:i]]; drop {
				continue
			}
		}
		newMethods[key] = m
	}
	// Add the new entries.
	for _, svc := range services {
		newServices[svc.Service] = svc
		for i := range svc.Methods {
			m := &svc.Methods[i]
			newMethods[methodKey(svc.Service, m.Name)] = m
		}
	}
	r.current.Store(&snapshot{
		methods:  newMethods,
		services: newServices,
	})
}

// Unregister removes a service and all its methods. Returns true when an
// entry was removed, false when the service was not present.
func (r *Registry) Unregister(service string) bool {
	if r == nil || service == "" {
		return false
	}
	old := r.current.Load()
	if _, present := old.services[service]; !present {
		return false
	}
	newMethods := make(map[string]*MethodSpec, len(old.methods))
	newServices := make(map[string]*ServiceSpec, len(old.services))
	for name, svc := range old.services {
		if name == service {
			continue
		}
		newServices[name] = svc
	}
	for key, m := range old.methods {
		i := strings.Index(key, "/")
		if i >= 0 && key[:i] == service {
			continue
		}
		newMethods[key] = m
	}
	r.current.Store(&snapshot{
		methods:  newMethods,
		services: newServices,
	})
	return true
}

// Clear empties the registry.
func (r *Registry) Clear() {
	if r == nil {
		return
	}
	r.current.Store(&snapshot{
		methods:  make(map[string]*MethodSpec),
		services: make(map[string]*ServiceSpec),
	})
}

// methodKey is the canonical Flow.Metadata lookup shape.
func methodKey(service, method string) string {
	return service + "/" + method
}

// sortServices orders services by Service name alphabetically. We don't
// pull in stdlib sort to keep the imports light; the typical N is small
// (handful of services per registration). Insertion sort is fine.
func sortServices(in []*ServiceSpec) {
	for i := 1; i < len(in); i++ {
		j := i
		for j > 0 && in[j-1].Service > in[j].Service {
			in[j-1], in[j] = in[j], in[j-1]
			j--
		}
	}
}

// LoadFileDescriptorSet parses a FileDescriptorSet payload and resolves
// every service it contains into a []*ServiceSpec ready for
// Registry.Register. The payload size MUST be checked against
// MaxDescriptorSetBytes before calling — callers that read the payload
// from a base64 input are responsible for that check.
//
// serviceFilter, when non-empty, restricts the returned services to the
// listed fully-qualified names. Services not in the filter are dropped
// AT REGISTER TIME (Resolved #6); the descriptor itself is still parsed
// fully so cross-service references resolve correctly.
//
// Returns an error citing protoc --include_imports when protodesc.NewFiles
// fails with a missing-dependency message — this is the most common
// failure mode for hand-built descriptor sets (Resolved #10).
func LoadFileDescriptorSet(raw []byte, serviceFilter []string) ([]*ServiceSpec, error) {
	if len(raw) == 0 {
		return nil, errors.New("descriptor_set bytes are empty")
	}
	if len(raw) > MaxDescriptorSetBytes {
		return nil, fmt.Errorf("descriptor_set size %d exceeds maximum %d bytes", len(raw), MaxDescriptorSetBytes)
	}

	specs, err := loadSafe(raw, serviceFilter)
	if err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		if len(serviceFilter) > 0 {
			return nil, fmt.Errorf("descriptor_set contains no services matching filter %v", serviceFilter)
		}
		return nil, errors.New("descriptor_set contains no services")
	}
	return specs, nil
}

// loadSafe wraps the protodesc / protoreflect calls in defer-recover so
// adversarial descriptor bytes that trigger a panic surface as a returned
// error (MITM principle 5).
func loadSafe(raw []byte, serviceFilter []string) (specs []*ServiceSpec, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during descriptor load: %v", r)
		}
	}()

	files, perr := parseAndResolveDescriptorSet(raw)
	if perr != nil {
		return nil, perr
	}
	filter := buildServiceFilter(serviceFilter)
	specs = collectServiceSpecs(files, filter)
	if vErr := verifyServiceFilterUsed(filter, specs); vErr != nil {
		return nil, vErr
	}
	return specs, nil
}

// parseAndResolveDescriptorSet parses the raw FileDescriptorSet bytes
// and resolves them into a protoregistry.Files. Returns a wrapped
// error citing protoc --include_imports when imports are missing.
func parseAndResolveDescriptorSet(raw []byte) (*protoregistry.Files, error) {
	fds := &descriptorpb.FileDescriptorSet{}
	if perr := proto.Unmarshal(raw, fds); perr != nil {
		return nil, fmt.Errorf("parse FileDescriptorSet: %w", perr)
	}
	files, perr := protodesc.NewFiles(fds)
	if perr != nil {
		if isMissingDependencyErr(perr) {
			return nil, fmt.Errorf("resolve FileDescriptorSet: %w (run `protoc --include_imports --descriptor_set_out=<file> <protos>` to include all transitive imports)", perr)
		}
		return nil, fmt.Errorf("resolve FileDescriptorSet: %w", perr)
	}
	return files, nil
}

// buildServiceFilter materialises the filter slice as a set for O(1)
// membership checks. Empty input or empty entries are skipped.
func buildServiceFilter(serviceFilter []string) map[string]struct{} {
	filter := make(map[string]struct{}, len(serviceFilter))
	for _, s := range serviceFilter {
		if s != "" {
			filter[s] = struct{}{}
		}
	}
	return filter
}

// collectServiceSpecs walks every file in the registry and projects
// matching services into ServiceSpec rows. An empty filter matches every
// service.
func collectServiceSpecs(files *protoregistry.Files, filter map[string]struct{}) []*ServiceSpec {
	var specs []*ServiceSpec
	now := time.Now().UTC()
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			svcDesc := services.Get(i)
			svcName := string(svcDesc.FullName())
			if len(filter) > 0 {
				if _, ok := filter[svcName]; !ok {
					continue
				}
			}
			specs = append(specs, buildServiceSpec(svcDesc, svcName, now))
		}
		return true
	})
	return specs
}

// buildServiceSpec assembles one ServiceSpec from a service descriptor.
func buildServiceSpec(svcDesc protoreflect.ServiceDescriptor, svcName string, now time.Time) *ServiceSpec {
	spec := &ServiceSpec{
		Service:      svcName,
		RegisteredAt: now,
	}
	methods := svcDesc.Methods()
	for j := 0; j < methods.Len(); j++ {
		md := methods.Get(j)
		inDesc := md.Input()
		outDesc := md.Output()
		spec.Methods = append(spec.Methods, MethodSpec{
			Name:       string(md.Name()),
			Input:      string(inDesc.FullName()),
			Output:     string(outDesc.FullName()),
			InputDesc:  inDesc,
			OutputDesc: outDesc,
		})
	}
	return spec
}

// verifyServiceFilterUsed errors if any entry in the user-supplied
// service_filter did not match a service in the descriptor set.
func verifyServiceFilterUsed(filter map[string]struct{}, specs []*ServiceSpec) error {
	if len(filter) == 0 || len(specs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(specs))
	for _, s := range specs {
		seen[s.Service] = struct{}{}
	}
	for name := range filter {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("service %q in service_filter not found in descriptor_set", name)
		}
	}
	return nil
}

// isMissingDependencyErr returns true when err looks like
// protodesc.NewFiles's "missing dependency" failure. protodesc uses
// "could not resolve import" wording across versions; we match on
// substrings rather than the concrete error type so a minor protoc
// upgrade doesn't silently swallow this branch.
func isMissingDependencyErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "could not resolve import") ||
		strings.Contains(s, "missing dependency") ||
		strings.Contains(s, "not found")
}

// Stats reports the current size of the registry.
type Stats struct {
	Services int
	Methods  int
}

// Stats returns counts of registered services and methods.
func (r *Registry) Stats() Stats {
	if r == nil {
		return Stats{}
	}
	s := r.current.Load()
	if s == nil {
		return Stats{}
	}
	return Stats{
		Services: len(s.services),
		Methods:  len(s.methods),
	}
}
