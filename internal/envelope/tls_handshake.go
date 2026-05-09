package envelope

// TLSHandshakeOutcome enumerates the canonical observation outcomes that
// the proxy can attribute to a TLS handshake event. These are recorded in
// TLSHandshakeMessage.Outcome and projected verbatim onto the Flow's
// Metadata["outcome"] entry by the recorder.
//
// USK-790 introduces these for the TLS passthrough audit-trail meta flow:
// the proxy never decrypts passthrough traffic, so it cannot positively
// observe a successful inner TLS handshake. The outcomes therefore reflect
// what the proxy itself observed at the TCP-relay boundary, not what the
// client and upstream negotiated end-to-end.
const (
	// TLSHandshakeOutcomeTunneled means the proxy successfully relayed the
	// raw TCP bytes between client and upstream for the entire connection
	// without observing a transport-level error. The TLS handshake itself
	// is opaque to the proxy under passthrough — it may have succeeded or
	// failed inside the tunnel; only the relay plumbing is reported as
	// healthy.
	TLSHandshakeOutcomeTunneled = "tunneled"

	// TLSHandshakeOutcomeFailed means the proxy could not establish or
	// maintain the relay. Common triggers: upstream TCP dial failure,
	// io.Copy returning a non-EOF error mid-relay, or the proxy aborting
	// the relay because the SNI peek timed out before a ClientHello arrived.
	TLSHandshakeOutcomeFailed = "failed"
)

// TLSHandshakeMessage represents a single audit-trail observation of a TLS
// connection that the proxy did not terminate. It is the typed Message
// payload for envelopes carrying ProtocolTLSHandshake. See RFC-001 §3.2.
//
// USK-790 motivation: when a host matches the proxy's TLS passthrough list
// the connector relays raw bytes via io.Copy without performing MITM.
// Before this Issue the connection produced no flow record at all, so an
// operator could not even tell whether a pinned host had been contacted.
// TLSHandshakeMessage carries exactly the observation surface the proxy
// has access to under passthrough — SNI peeked from the first TLS record,
// 4-tuple addresses, byte counters drained from the relay, and the relay
// outcome — so the audit trail captures "a connection happened to host X"
// without violating the passthrough contract (no decryption, no inner-
// protocol introspection).
//
// Fidelity rule: every field reflects what the proxy itself observed. ALPN
// and the negotiated TLS version are intentionally absent because the
// proxy does not see them under passthrough; recording them would
// fabricate data the wire never showed us.
type TLSHandshakeMessage struct {
	// SNI is the server_name extension value extracted from the client's
	// first TLS ClientHello. Empty when:
	//   - the client did not send the SNI extension (rare on the modern
	//     web but legal),
	//   - the first record was not a ClientHello (TLS-over-something-else
	//     or a malformed first record), or
	//   - the SNI peek timed out / errored before any bytes arrived.
	// When non-empty it is the verbatim host string the client placed in
	// the extension — case-preserved per the wire (no normalization).
	SNI string

	// LocalAddr is the proxy-side local address of the client-facing TCP
	// socket, formatted as host:port (net.Addr.String()). For an IPv4
	// listener bound to "127.0.0.1:8080" with ephemeral upstream port, the
	// value is the listener's bound address.
	LocalAddr string

	// RemoteAddr is the client's remote address, formatted as host:port
	// (net.Addr.String()). This is the connecting peer the proxy accepted.
	RemoteAddr string

	// UpstreamAddr is the resolved upstream address dialed by the proxy
	// for the passthrough relay, formatted as host:port. Set after the
	// upstream TCP dial succeeds; left empty when the dial itself failed
	// (in which case Outcome is "failed" and ErrorReason explains why).
	UpstreamAddr string

	// BytesClientToUpstream counts the bytes the proxy relayed from the
	// client side to the upstream side via io.Copy. Includes the full TLS
	// record stream observed during the lifetime of the relay; the proxy
	// does not split TLS records out of this counter (it cannot — it does
	// not parse them).
	BytesClientToUpstream int64

	// BytesUpstreamToClient counts the bytes the proxy relayed from the
	// upstream side to the client side. Same semantics as
	// BytesClientToUpstream, in the opposite direction.
	BytesUpstreamToClient int64

	// Outcome is one of the TLSHandshakeOutcome* constants and reflects
	// the proxy's view of the relay, NOT the inner TLS handshake's view
	// (which is opaque under passthrough). See the constant docs for the
	// canonical values.
	Outcome string

	// ErrorReason carries a short human-readable explanation when Outcome
	// is "failed". Empty for a successful tunnel. The verbatim error
	// string is intentionally short: the proxy treats this as audit
	// metadata, not a primary diagnostic surface — operators correlate it
	// with peer-side logs (tcpdump, server access logs).
	ErrorReason string
}

// Protocol returns ProtocolTLSHandshake.
func (m *TLSHandshakeMessage) Protocol() Protocol { return ProtocolTLSHandshake }

// CloneMessage returns a deep copy of the TLSHandshakeMessage. Every field
// is value-typed (strings and int64s) so the copy is straightforward.
func (m *TLSHandshakeMessage) CloneMessage() Message {
	if m == nil {
		return nil
	}
	clone := *m
	return &clone
}
