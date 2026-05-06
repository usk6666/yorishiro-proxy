# http_mock.star
#
# Intercepts HTTP requests to a specific path and returns a mock response
# instead of forwarding upstream. Demonstrates the typed action.RESPOND
# builtin (RFC-001 §9.3 D5; pluginv2 USK-671).
#
# Hook identity (RFC-001 §9.3):
#   register_hook("http", "on_request", fn)
#
# action.RESPOND is valid only on transaction-start events (http.on_request,
# ws.on_upgrade, grpc.on_start, ...) — see internal/pluginv2/surface.go.
#
# Plugin config:
#   {
#     "path": "examples/plugins/http_mock.star",
#     "on_error": "skip"
#   }

MOCK_PATH = "/api/v1/health"
MOCK_BODY = b'{"status":"ok","version":"1.0.0","mocked":true}'

def mock_health(msg, ctx):
    """Return a synthetic 200 response for requests to the health endpoint."""
    if MOCK_PATH in msg["path"]:
        print("http_mock: mocking %s" % msg["path"])
        return action.RESPOND(
            status_code = 200,
            headers = [
                ("Content-Type", "application/json"),
                ("X-Mock", "true"),
            ],
            body = MOCK_BODY,
        )
    return None  # CONTINUE

register_hook("http", "on_request", mock_health)
