# socks5_logger.star
#
# Logs SOCKS5 CONNECT events: which client established a tunnel to which
# destination. Useful for monitoring proxy egress.
#
# Hook identity (RFC-001 §9.3):
#   register_hook("socks5", "on_connect", fn)
#
# `(socks5, on_connect)` is a lifecycle event — `phase=` must NOT be passed
# (PhaseSupportNone in internal/pluginv2/surface.go). The dict shape comes
# from BuildSOCKS5ConnectDict (internal/pluginv2/lifecycle.go):
#   conn_id / client_addr / target_addr
# Returning action.DROP refuses the tunnel; CONTINUE lets it proceed.
#
# Plugin config:
#   {
#     "path": "examples/plugins/socks5_logger.star",
#     "on_error": "skip"
#   }

def log_socks5_connect(msg, ctx):
    """Log SOCKS5 tunnel establishment details."""
    print("SOCKS5 CONNECT: target=%s client=%s conn=%s" % (
        msg["target_addr"], msg["client_addr"], msg["conn_id"]))
    return None  # CONTINUE

register_hook("socks5", "on_connect", log_socks5_connect)
