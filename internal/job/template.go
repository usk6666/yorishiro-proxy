package job

import (
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/macro"
)

// ExpandEnvelopeTemplates applies §variable§ template expansion to the
// Envelope's Message fields using the given KV store. Dispatches by Message
// type: HTTPMessage fields and RawMessage bytes.
//
// Returns an error if template expansion fails (e.g., unknown encoder in
// a pipe chain). Unknown variables are left as-is per macro.ExpandTemplate
// semantics.
func ExpandEnvelopeTemplates(env *envelope.Envelope, kvStore map[string]string) error {
	if env == nil || env.Message == nil || len(kvStore) == 0 {
		return nil
	}

	switch m := env.Message.(type) {
	case *envelope.HTTPMessage:
		return expandHTTPMessage(m, kvStore)
	case *envelope.RawMessage:
		return expandRawMessage(m, kvStore)
	default:
		// Unknown message types pass through without expansion.
		return nil
	}
}

// expandHTTPMessage applies template expansion to HTTP request fields:
// Method, Path, RawQuery, header values, and Body.
func expandHTTPMessage(m *envelope.HTTPMessage, kvStore map[string]string) error {
	var err error

	if m.Method, err = macro.ExpandTemplate(m.Method, kvStore); err != nil {
		return fmt.Errorf("expand Method: %w", err)
	}
	if m.Path, err = macro.ExpandTemplate(m.Path, kvStore); err != nil {
		return fmt.Errorf("expand Path: %w", err)
	}
	if m.RawQuery, err = macro.ExpandTemplate(m.RawQuery, kvStore); err != nil {
		return fmt.Errorf("expand RawQuery: %w", err)
	}
	if m.Authority, err = macro.ExpandTemplate(m.Authority, kvStore); err != nil {
		return fmt.Errorf("expand Authority: %w", err)
	}

	for i := range m.Headers {
		if m.Headers[i].Value, err = macro.ExpandTemplate(m.Headers[i].Value, kvStore); err != nil {
			return fmt.Errorf("expand header %q: %w", m.Headers[i].Name, err)
		}
	}

	if m.Body != nil {
		expanded, err := macro.ExpandTemplate(string(m.Body), kvStore)
		if err != nil {
			return fmt.Errorf("expand Body: %w", err)
		}
		m.Body = []byte(expanded)
	}

	return nil
}

// expandRawMessage applies template expansion to the raw bytes treated as
// a string. This allows §variable§ markers embedded in raw payloads.
func expandRawMessage(m *envelope.RawMessage, kvStore map[string]string) error {
	if m.Bytes == nil {
		return nil
	}
	expanded, err := macro.ExpandTemplate(string(m.Bytes), kvStore)
	if err != nil {
		return fmt.Errorf("expand raw bytes: %w", err)
	}
	m.Bytes = []byte(expanded)
	return nil
}
