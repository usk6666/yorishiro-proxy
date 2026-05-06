# grpc_logger.star
#
# Observe-only gRPC plugin: logs the service/method path of each call.
#
# Hook identity (RFC-001 §9.3):
#   register_hook("grpc", "on_start", fn)
#
# `(grpc, on_start)` is the transaction-start event for gRPC calls — fired
# once per stream when the proxy first sees the request HEADERS frame
# (HPACK :path = "/<service>/<method>"). The Starlark dict shape is
# *envelope.GRPCStartMessage projected via internal/pluginv2/convert.go:
# service / method / metadata / timeout / content_type / encoding /
# accept_encoding / anomalies (read-only).
#
# Plugin config:
#   {
#     "path": "examples/plugins/grpc_logger.star",
#     "on_error": "skip"
#   }

def log_grpc_start(msg, ctx):
    """Log the gRPC method path for monitoring."""
    full_path = "/" + msg["service"] + "/" + msg["method"]
    print("gRPC call: path=%s content_type=%s" % (full_path, msg["content_type"]))
    return None  # CONTINUE

register_hook("grpc", "on_start", log_grpc_start)
