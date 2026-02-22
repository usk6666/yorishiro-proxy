package protocol

import (
	"github.com/usk6666/katashiro-proxy/internal/proxy"
)

// Detector selects the appropriate protocol handler based on peeked bytes.
type Detector struct {
	handlers []proxy.ProtocolHandler
}

// NewDetector creates a Detector with the given handlers in priority order.
func NewDetector(handlers ...proxy.ProtocolHandler) *Detector {
	return &Detector{handlers: handlers}
}

// Detect examines peek bytes and returns the first matching handler, or nil.
func (d *Detector) Detect(peek []byte) proxy.ProtocolHandler {
	for _, h := range d.handlers {
		if h.Detect(peek) {
			return h
		}
	}
	return nil
}
