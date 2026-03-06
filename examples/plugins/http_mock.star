# http_mock.star
#
# Intercepts HTTP requests to a specific path and returns a mock response
# instead of forwarding to the upstream server.
#
# Configuration:
#   protocol: "http" (also works with "https" and "h2")
#   hooks: ["on_receive_from_client"]
#
# Usage example (plugin config):
#   {
#     "path": "examples/plugins/http_mock.star",
#     "protocol": "http",
#     "hooks": ["on_receive_from_client"]
#   }

# The URL path to mock.
MOCK_PATH = "/api/v1/health"

# The mock response to return.
MOCK_STATUS = 200
MOCK_BODY = '{"status":"ok","version":"1.0.0","mocked":true}'
MOCK_CONTENT_TYPE = "application/json"

def on_receive_from_client(data):
    """Return a mock response for requests to the health endpoint."""
    url = data.get("url", "")

    # Check if the URL path matches our mock target.
    # The url field contains the full URL; we check if it ends with or
    # contains the mock path.
    if MOCK_PATH in url:
        print("http_mock: responding with mock for %s" % url)
        return {
            "action": action.RESPOND,
            "response": {
                "status_code": MOCK_STATUS,
                "headers": {
                    "Content-Type": MOCK_CONTENT_TYPE,
                    "X-Mock": "true",
                },
                "body": MOCK_BODY,
            },
        }

    return {"action": action.CONTINUE}
