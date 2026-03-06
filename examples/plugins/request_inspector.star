# request_inspector.star
#
# HTTP Request Inspector - inspects and annotates HTTP requests for testing.
# Logs request details (method, URL, headers) to the proxy log via print(),
# and injects tracking headers so plugin activity is visible in flow records.
#
# This plugin uses two hooks:
#   - on_receive_from_client: logs incoming request details
#   - on_before_send_to_server: adds tracking headers to outgoing requests
#
# Configuration:
#   protocol: "http" (also works with "https" and "h2")
#   hooks: ["on_receive_from_client", "on_before_send_to_server"]
#   on_error: "skip"
#
# Usage example (plugin config):
#   {
#     "path": "examples/plugins/request_inspector.star",
#     "protocol": "http",
#     "hooks": ["on_receive_from_client", "on_before_send_to_server"],
#     "on_error": "skip"
#   }

def on_receive_from_client(data):
    """Log incoming request details."""
    method = data.get("method", "?")
    url = data.get("url", "?")
    headers = data.get("headers", {})
    content_type = headers.get("Content-Type", headers.get("content-type", "none"))

    print("[inspector] %s %s (Content-Type: %s)" % (method, url, content_type))

    header_count = len(headers)
    print("[inspector] request has %d headers" % header_count)

    return {"action": action.CONTINUE}

def on_before_send_to_server(data):
    """Add tracking headers to the outgoing request."""
    headers = data.get("headers", {})
    headers["X-Yorishiro-Inspected"] = "true"
    headers["X-Yorishiro-Method"] = data.get("method", "UNKNOWN")
    data["headers"] = headers

    print("[inspector] added tracking headers to %s" % data.get("url", "?"))
    return {"action": action.CONTINUE, "data": data}
