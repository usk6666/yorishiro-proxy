# grpc_logger.star
#
# Observe-only plugin that logs gRPC method paths.
# gRPC plugins can only use action.CONTINUE (observe-only mode).
#
# Configuration:
#   protocol: "grpc"
#   hooks: ["on_receive_from_client"]
#
# Usage example (plugin config):
#   {
#     "path": "examples/plugins/grpc_logger.star",
#     "protocol": "grpc",
#     "hooks": ["on_receive_from_client"]
#   }

def on_receive_from_client(data):
    """Log gRPC method path for monitoring."""
    method = data.get("url", "unknown")
    protocol = data.get("protocol", "")
    print("gRPC call: method=%s protocol=%s" % (method, protocol))
    return {"action": action.CONTINUE}
