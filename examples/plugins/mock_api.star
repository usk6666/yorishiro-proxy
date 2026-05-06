# mock_api.star
#
# Returns mock responses for several API paths. Same shape as http_mock.star
# but iterates over a tuple of routes — useful for stubbing a flat set of
# endpoints during local development.
#
# Hook identity (RFC-001 §9.3):
#   register_hook("http", "on_request", fn)
#
# Plugin config:
#   {
#     "path": "examples/plugins/mock_api.star",
#     "on_error": "skip"
#   }

# Module-level vars are frozen after script load. Use immutable types
# (tuple of strings) so reads inside the hook do not trip frozen-write errors.
MOCK_ROUTES = (
    "/api/v1/health",
    "/api/v1/status",
)

def mock_routes(msg, ctx):
    path = msg["path"]
    method = msg["method"]
    for route in MOCK_ROUTES:
        if route in path:
            print("[mock_api] %s %s -> mock" % (method, path))
            return action.RESPOND(
                status_code = 200,
                headers = [
                    ("Content-Type", "application/json"),
                    ("X-Mock", "true"),
                ],
                # action.RESPOND.body accepts both str and bytes
                # (internal/pluginv2/respond_action.go).
                body = '{"path":"%s","mock":true,"status":"ok"}' % route,
            )
    return None  # CONTINUE

register_hook("http", "on_request", mock_routes)
