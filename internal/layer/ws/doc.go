// Package ws provides the byte-level WebSocket frame codec (RFC 6455) and
// per-message-deflate state machine (RFC 7692) used by the WSLayer.
//
// This package contains only wire-level primitives: frame Read/Write,
// opcode constants, and deflate context-takeover decompression. The
// envelope-level structured view ([envelope.WSMessage]) and the Layer
// interface implementation belong in sibling files added by later
// issues; see RFC-001 §3.2.2 and §3.3.2.
//
// Note: a parallel copy of frame.go and deflate.go exists in
// internal/protocol/ws/ during the RFC-001 transition. The legacy copy
// is consumed by internal/protocol/ws/handler.go and the existing
// resend code path; both are scheduled for removal in N9 once feature
// parity is reached.
package ws
