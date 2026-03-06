# ws_filter.star
#
# Filters WebSocket messages based on content patterns.
# Messages containing the blocked pattern are dropped; all others
# are passed through.
#
# Configuration:
#   protocol: "websocket"
#   hooks: ["on_receive_from_client"]
#
# Usage example (plugin config):
#   {
#     "path": "examples/plugins/ws_filter.star",
#     "protocol": "websocket",
#     "hooks": ["on_receive_from_client"]
#   }

# Pattern to block. Messages containing this string are dropped.
BLOCKED_PATTERN = "FORBIDDEN_COMMAND"

def on_receive_from_client(data):
    """Drop WebSocket messages containing the blocked pattern."""
    payload = data.get("payload", "")

    # Only filter text messages.
    is_text = data.get("is_text", False)
    if not is_text:
        return {"action": action.CONTINUE}

    if BLOCKED_PATTERN in payload:
        print("ws_filter: dropping message containing '%s'" % BLOCKED_PATTERN)
        return {"action": action.DROP}

    return {"action": action.CONTINUE}
