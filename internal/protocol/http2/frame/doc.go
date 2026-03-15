// Package frame implements a low-level HTTP/2 frame codec per RFC 9113.
//
// It provides reading and writing of all HTTP/2 frame types with raw bytes
// preservation. The codec operates at the frame level without interpreting
// higher-level semantics such as HPACK header compression or stream
// state management.
//
// Key design decisions:
//   - Each frame retains its raw bytes for L4 recording
//   - Frame size limits (SETTINGS_MAX_FRAME_SIZE) are enforced on read
//   - No external dependencies beyond the Go standard library
//
// The codec enforces per-frame size limits but does not manage
// connection-level resource constraints. Callers are responsible for
// enforcing connection-level limits such as total bytes read/written,
// maximum number of frames, and read/write timeouts.
package frame
