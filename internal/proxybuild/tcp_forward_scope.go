package proxybuild

import (
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// tcpForwardScopeCheck is the TCP forward gate's scope check (USK-1161).
// SCAFFOLD: always allows; implemented in the green commit.
func tcpForwardScopeCheck(_ *connector.TargetScope, _ string, _ bool) (allowed bool, reason string) {
	return true, ""
}
