# ws_filter.star
#
# Redacts WebSocket text frames containing a forbidden pattern. Demonstrates
# in-place mutation of msg["payload"] at the (ws, on_message) hook.
#
# Hook identity (RFC-001 §9.3):
#   register_hook("ws", "on_message", fn)
#
# Mid-stream events accept CONTINUE only — terminating a WebSocket session
# uses a native close frame, not action.DROP (see internal/pluginv2/surface.go).
# To stop a flow, the operator should configure an Intercept rule or close
# the upstream Channel; plugins observe and rewrite, they do not terminate.
#
# The Starlark dict shape mirrors *envelope.WSMessage: opcode / fin / masked /
# mask / payload (bytes) / close_code / close_reason / compressed.
# Opcode values: 0x1 = text, 0x2 = binary, 0x8 = close, 0x9 = ping, 0xA = pong.
#
# Plugin config:
#   {
#     "path": "examples/plugins/ws_filter.star",
#     "on_error": "skip"
#   }

WS_OPCODE_TEXT = 1
BLOCKED_PATTERN = b"FORBIDDEN_COMMAND"
REDACTION = b"[redacted by ws_filter]"

def redact_blocked(msg, ctx):
    """Replace text payloads matching BLOCKED_PATTERN with a redaction marker."""
    # Only inspect text frames; binary/control frames are passed through.
    if msg["opcode"] != WS_OPCODE_TEXT:
        return None

    payload = msg["payload"]
    if BLOCKED_PATTERN in payload:
        print("ws_filter: redacting message containing %r" % BLOCKED_PATTERN)
        msg["payload"] = REDACTION
    return None  # CONTINUE

register_hook("ws", "on_message", redact_blocked)
