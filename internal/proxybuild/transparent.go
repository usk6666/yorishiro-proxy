package proxybuild

import "github.com/usk6666/yorishiro-proxy/internal/connector"

// transparentSupported reports whether the platform REDIRECT resolver
// works here. A variable so tests can exercise the unsupported-platform
// error on Linux.
var transparentSupported = connector.TransparentSupported
