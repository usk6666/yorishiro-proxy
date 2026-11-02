package proxybuild

import (
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// HTTPBodyModeEngines are the live engines an HTTP body-mode predicate
// consults (USK-1409). Any field may be nil.
type HTTPBodyModeEngines struct {
	Safety    *httprules.SafetyEngine
	Intercept *httprules.InterceptEngine
	Transform *httprules.TransformEngine
	Plugin    *pluginv2.Engine
}

// NewHTTPBodyModeFunc returns the body-mode predicate for HTTP messages.
// Not implemented yet (USK-1409 scaffolding): buffers every body.
func NewHTTPBodyModeFunc(e HTTPBodyModeEngines) layer.BodyModeFunc {
	return func(env *envelope.Envelope, msg *envelope.HTTPMessage) layer.BodyMode {
		return layer.Buffer()
	}
}
