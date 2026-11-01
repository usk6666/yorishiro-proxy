package http1

// WithForwardProxyOriginForm marks a Send-direction (client-facing) Layer
// as the ingress of the explicit plain-HTTP forward proxy.
func WithForwardProxyOriginForm() Option {
	return func(o *options) { o.forwardOriginForm = true }
}

// stripForwardProxyHeaders is a Phase 1 scaffold.
func stripForwardProxyHeaders(tail []byte) []byte { return tail }
