package ws

// Role identifies whether the wrapped wire is the client-facing side
// (the local endpoint behaves as the WebSocket server) or the upstream-
// facing side (the local endpoint behaves as the WebSocket client).
//
// The convention mirrors internal/layer/grpc and internal/layer/http2:
//
//   - RoleServer: client-facing. Reads expect MASKED frames per RFC 6455
//     §5.3 ("client-to-server frames MUST be masked"); incoming envelopes
//     carry Direction=Send. Writes emit UNMASKED frames carrying
//     Direction=Receive.
//
//   - RoleClient: upstream-facing. Reads expect UNMASKED frames; incoming
//     envelopes carry Direction=Receive. Writes emit MASKED frames
//     carrying Direction=Send. The 4-byte mask key is regenerated per
//     frame from crypto/rand.
//
// The Layer does not enforce wire mask correctness — a peer that violates
// RFC 6455 §5.1 (server sending masked frame, or client sending unmasked
// frame) is recorded faithfully via Envelope.Raw and surfaced through the
// observed WSMessage.Masked / WSMessage.Mask fields. MITM principle: the
// proxy reports what the wire said, not what the wire should have said.
type Role uint8

const (
	// RoleServer indicates the local endpoint is the WebSocket server
	// (client-facing layer instance).
	RoleServer Role = iota
	// RoleClient indicates the local endpoint is the WebSocket client
	// (upstream-facing layer instance).
	RoleClient
)
