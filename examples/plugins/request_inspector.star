# request_inspector.star
#
# HTTP Request Inspector — logs incoming requests and stamps tracking
# headers on outgoing ones.
#
# This plugin demonstrates registering two hooks at distinct phases on the
# same (protocol, event) — pre_pipeline observes the request as the client
# sent it, post_pipeline stamps after Intercept/Transform have settled.
#
# Hook identity (RFC-001 §9.3):
#   register_hook("http", "on_request", log_request)                  # pre_pipeline (default)
#   register_hook("http", "on_request", stamp_request, phase="post_pipeline")
#
# Plugin config (examples/config_with_plugins.json):
#   {
#     "path": "examples/plugins/request_inspector.star",
#     "on_error": "skip"
#   }

def log_request(msg, ctx):
    """Log the request as observed on the wire (pre_pipeline)."""
    method = msg["method"]
    path = msg["path"]
    # HeadersValue exposes get_first(name) — case-insensitive, returns
    # None when no match. Use `or` to default for printing.
    content_type = msg["headers"].get_first("Content-Type") or "none"
    print("[inspector] %s %s (Content-Type: %s, headers=%d)" % (
        method, path, content_type, len(msg["headers"])))
    return None  # CONTINUE

def stamp_request(msg, ctx):
    """Append tracking headers after Intercept/Transform (post_pipeline)."""
    msg["headers"].append("X-Yorishiro-Inspected", "true")
    msg["headers"].append("X-Yorishiro-Method", msg["method"])
    print("[inspector] stamped tracking headers on %s" % msg["path"])
    return None  # CONTINUE

register_hook("http", "on_request", log_request)
register_hook("http", "on_request", stamp_request, phase="post_pipeline")
