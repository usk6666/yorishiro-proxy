// Package envelope defines the protocol-agnostic message container for
// yorishiro-proxy's Envelope + Layered Connection Model (RFC-001).
//
// An [Envelope] is the outer container that flows through the Pipeline.
// It carries identity (StreamID, FlowID, Sequence, Direction), wire-observed
// raw bytes, a typed [Message] payload, cross-layer context, and opaque
// layer-internal state.
//
// The [Message] interface is implemented by protocol-specific types:
// [HTTPMessage], [RawMessage], and (in future milestones) WSMessage,
// GRPCMessage, SSEMessage, TLSHandshakeMessage.
//
// Design rule: any field on Envelope must be meaningful for every protocol,
// including raw TCP. Protocol-specific fields belong on Message implementations.
package envelope
