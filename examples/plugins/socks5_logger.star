# socks5_logger.star
#
# Logs SOCKS5 CONNECT events including target, authentication method,
# and client address. This is useful for monitoring which destinations
# are accessed through the SOCKS5 proxy.
#
# Configuration:
#   protocol: "socks5"
#   hooks: ["on_socks5_connect"]
#
# Usage example (plugin config):
#   {
#     "path": "examples/plugins/socks5_logger.star",
#     "protocol": "socks5",
#     "hooks": ["on_socks5_connect"]
#   }

def on_socks5_connect(data):
    """Log SOCKS5 tunnel establishment details."""
    target = data.get("target", "unknown")
    auth_method = data.get("auth_method", "unknown")
    auth_user = data.get("auth_user", "")
    client_addr = data.get("client_addr", "unknown")

    if auth_user:
        print("SOCKS5 CONNECT: target=%s auth=%s user=%s client=%s" % (
            target, auth_method, auth_user, client_addr))
    else:
        print("SOCKS5 CONNECT: target=%s auth=%s client=%s" % (
            target, auth_method, client_addr))

    return {"action": action.CONTINUE}
