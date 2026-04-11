package connector

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestDetectKind(t *testing.T) {
	tests := []struct {
		name string
		peek []byte
		want ProtocolKind
	}{
		{"empty", []byte{}, ProtocolUnknown},
		{"nil", nil, ProtocolUnknown},

		// SOCKS5: single 0x05 byte.
		{"socks5 single byte", []byte{0x05}, ProtocolSOCKS5},
		{"socks5 with greeting", []byte{0x05, 0x02, 0x00, 0x02}, ProtocolSOCKS5},

		// CONNECT: requires exact prefix with trailing space.
		{"http connect", []byte("CONNECT example.com:443"), ProtocolHTTPConnect},
		{"http connect full", []byte("CONNECT example.com:443 HTTP/1.1\r\n"), ProtocolHTTPConnect},
		{"http connected (negative)", []byte("CONNECTED "), ProtocolTCP},

		// HTTP methods: known methods with trailing space.
		{"get", []byte("GET / HTTP/1.1"), ProtocolHTTP1},
		{"post", []byte("POST /api/x HT"), ProtocolHTTP1},
		{"put", []byte("PUT /foo HTTP/1"), ProtocolHTTP1},
		{"delete", []byte("DELETE /x HTTP/"), ProtocolHTTP1},
		{"head", []byte("HEAD /x HTTP/1.1"), ProtocolHTTP1},
		{"options", []byte("OPTIONS * HTTP/1.1"), ProtocolHTTP1},
		{"patch", []byte("PATCH /x HTTP/1."), ProtocolHTTP1},
		{"trace", []byte("TRACE /x HTTP/1.1"), ProtocolHTTP1},

		// Short HTTP method read that is still consistent — allowed by
		// stage 1 so the listener retries in stage 2.
		{"short get", []byte("GE"), ProtocolHTTP1},
		{"short post", []byte("POS"), ProtocolHTTP1},

		// Unknown method should fall through to TCP.
		{"unknown method", []byte("BREW / HTTP/1.1"), ProtocolTCP},

		// h2c connection preface.
		{"h2c preface", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), ProtocolHTTP2},
		{"h2c first 8", []byte("PRI * HT"), ProtocolHTTP2},
		{"h2c short 7", []byte("PRI * H"), ProtocolTCP}, // not enough bytes

		// Raw TCP fall-through.
		{"binary", []byte{0xFF, 0xFE, 0xFD, 0x00}, ProtocolTCP},
		{"single letter", []byte{'A'}, ProtocolTCP},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := DetectKind(tt.peek)
			if got != tt.want {
				t.Errorf("DetectKind(%q) = %v, want %v", tt.peek, got, tt.want)
			}
		})
	}
}

// fakeFactory is a test CodecFactory that records its ProtocolKind.
type fakeFactory struct {
	kind ProtocolKind
	id   int
}

func (f *fakeFactory) Kind() ProtocolKind { return f.kind }

func TestDetector_RegisterAndLookup(t *testing.T) {
	d := NewDetector()

	// Unknown kind returns nil.
	if got := d.Lookup(ProtocolHTTP1); got != nil {
		t.Errorf("Lookup(HTTP1) before Register = %v, want nil", got)
	}

	f1 := &fakeFactory{kind: ProtocolHTTP1, id: 1}
	d.Register(ProtocolHTTP1, f1)
	if got := d.Lookup(ProtocolHTTP1); got != f1 {
		t.Errorf("Lookup(HTTP1) = %v, want %v", got, f1)
	}

	// Re-registering overrides (so tests can inject mocks).
	f2 := &fakeFactory{kind: ProtocolHTTP1, id: 2}
	d.Register(ProtocolHTTP1, f2)
	if got := d.Lookup(ProtocolHTTP1); got != f2 {
		t.Errorf("Lookup(HTTP1) after override = %v, want %v", got, f2)
	}

	// Register(nil) clears the entry.
	d.Register(ProtocolHTTP1, nil)
	if got := d.Lookup(ProtocolHTTP1); got != nil {
		t.Errorf("Lookup(HTTP1) after nil = %v, want nil", got)
	}
}

func TestDetector_Detect(t *testing.T) {
	d := NewDetector()
	httpFactory := &fakeFactory{kind: ProtocolHTTP1, id: 1}
	tcpFactory := &fakeFactory{kind: ProtocolTCP, id: 2}
	d.Register(ProtocolHTTP1, httpFactory)
	d.Register(ProtocolTCP, tcpFactory)

	tests := []struct {
		name    string
		peek    []byte
		kind    ProtocolKind
		factory CodecFactory
	}{
		{"http", []byte("GET / HTTP/1.1"), ProtocolHTTP1, httpFactory},
		{"tcp", []byte{0xFF, 0xFE}, ProtocolTCP, tcpFactory},
		// HTTP/2 detected but no factory registered — kind is returned
		// with a nil factory so callers can log the decision.
		{"h2c no factory", []byte("PRI * HT"), ProtocolHTTP2, nil},
		{"empty", nil, ProtocolUnknown, nil},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			k, f := d.Detect(tt.peek)
			if k != tt.kind {
				t.Errorf("Detect kind = %v, want %v", k, tt.kind)
			}
			if f != tt.factory {
				t.Errorf("Detect factory = %v, want %v", f, tt.factory)
			}
		})
	}
}

// TestDetector_ConcurrentAccess exercises the RWMutex in Register/Lookup.
// Runs under -race; the test is a smoke check that there are no data races
// between concurrent registrations and lookups.
func TestDetector_ConcurrentAccess(t *testing.T) {
	d := NewDetector()

	const goroutines = 32
	const iterations = 200
	var wg sync.WaitGroup
	var lookups atomic.Int64

	// Producers register factories.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				d.Register(ProtocolHTTP1, &fakeFactory{kind: ProtocolHTTP1, id: id*iterations + j})
			}
		}(i)
	}
	// Consumers look up concurrently.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if f := d.Lookup(ProtocolHTTP1); f != nil {
					lookups.Add(1)
				}
			}
		}()
	}
	wg.Wait()
}
