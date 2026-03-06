# Mock API Plugin
#
# Purpose: Return mock responses for specific API paths.
#          Tests the action.RESPOND pattern and selective path matching.
#
# Config:
#   protocol: "http"
#   hooks: ["on_receive_from_client"]
#   on_error: "skip"

MOCK_ROUTES = (
    "/api/v1/health",
    "/api/v1/status",
)

def on_receive_from_client(data):
    url = data.get("url", "")
    method = data.get("method", "")

    for route in MOCK_ROUTES:
        if route in url:
            print("[mock_api] intercepted %s %s -> returning mock response" % (method, url))
            return {
                "action": action.RESPOND,
                "response": {
                    "status_code": 200,
                    "headers": {
                        "Content-Type": "application/json",
                        "X-Mock": "true",
                    },
                    "body": '{"path":"%s","mock":true,"status":"ok"}' % route,
                },
            }

    print("[mock_api] passing through %s %s" % (method, url))
    return {"action": action.CONTINUE}
