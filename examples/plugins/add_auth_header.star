# add_auth_header.star
#
# Injects an Authorization header into outgoing HTTP requests.
# This plugin runs in the on_before_send_to_server hook, which is
# called after transform rules and before recording.
#
# Configuration:
#   protocol: "http" (also works with "https" and "h2")
#   hooks: ["on_before_send_to_server"]
#
# Usage example (plugin config):
#   {
#     "path": "examples/plugins/add_auth_header.star",
#     "protocol": "http",
#     "hooks": ["on_before_send_to_server"]
#   }

# The token to inject. In a real scenario, this could be read from
# an environment variable or a file.
AUTH_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example"

def on_before_send_to_server(data):
    """Add an Authorization header to the outgoing request."""
    headers = data.get("headers", {})
    headers["Authorization"] = AUTH_TOKEN
    data["headers"] = headers
    return {"action": action.CONTINUE, "data": data}
