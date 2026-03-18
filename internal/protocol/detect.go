package protocol

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// Detector selects the appropriate protocol handler based on peeked bytes.
type Detector struct {
	handlers []proxy.ProtocolHandler
	logger   *slog.Logger
}

// NewDetector creates a Detector with the given handlers in priority order.
func NewDetector(handlers ...proxy.ProtocolHandler) *Detector {
	return &Detector{handlers: handlers, logger: slog.Default()}
}

// SetLogger sets the logger used for debug-level protocol detection logging.
func (d *Detector) SetLogger(logger *slog.Logger) {
	if logger != nil {
		d.logger = logger
	}
}

// Detect examines peek bytes and returns the first matching handler, or nil.
func (d *Detector) Detect(peek []byte) proxy.ProtocolHandler {
	debugEnabled := d.logger.Enabled(context.Background(), slog.LevelDebug)

	var start time.Time
	var previewLen int
	if debugEnabled {
		start = time.Now()

		// Log leading bytes for diagnostics (up to 8 bytes).
		previewLen = len(peek)
		if previewLen > 8 {
			previewLen = 8
		}
	}

	for _, h := range d.handlers {
		if h.Detect(peek) {
			if debugEnabled {
				d.logger.Debug("protocol detected",
					"protocol", h.Name(),
					"peek_hex", fmt.Sprintf("%x", peek[:previewLen]),
					"peek_len", len(peek),
					"duration_us", time.Since(start).Microseconds(),
				)
			}
			return h
		}
	}

	if debugEnabled {
		d.logger.Debug("no protocol matched",
			"peek_hex", fmt.Sprintf("%x", peek[:previewLen]),
			"peek_len", len(peek),
			"duration_us", time.Since(start).Microseconds(),
		)
	}
	return nil
}
