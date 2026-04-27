package envelope

// gRPC-Web specific anomaly types. Detected by the gRPC-Web Layer when an
// inbound HTTPMessage body fails to parse and the failure is recoverable
// (i.e. wire-format observability signal, not a security cap). Stream-
// terminating problems (oversize LPM, gzip-bomb cap, unsupported encoding)
// continue to surface as *layer.StreamError instead of these anomalies —
// they are termination contracts, not parser deviations.
const (
	// AnomalyMalformedGRPCWebBase64 marks a request or response whose
	// content-type advertises grpc-web-text but whose body is not valid
	// base64. The malformed body bytes are preserved verbatim on
	// Envelope.Raw so an analyst running a fuzzer can see what was sent.
	AnomalyMalformedGRPCWebBase64 AnomalyType = "MalformedGRPCWebBase64"

	// AnomalyMalformedGRPCWebLPM marks a body whose length-prefixed
	// message framing is malformed: incomplete 5-byte header, invalid
	// flags byte (bits other than compressed=0x01 and trailer=0x80), or
	// declared payload length exceeds the remaining bytes. All three
	// variants share this single anomaly because they are different
	// shapes of the same root cause: the LPM stream is not a valid
	// concatenation of well-formed frames.
	AnomalyMalformedGRPCWebLPM AnomalyType = "MalformedGRPCWebLPM"

	// AnomalyMalformedGRPCWebTrailer marks an embedded trailer frame
	// whose text payload could not be parsed as "name: value\r\n" lines.
	AnomalyMalformedGRPCWebTrailer AnomalyType = "MalformedGRPCWebTrailer"
)
