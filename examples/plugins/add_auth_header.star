# add_auth_header.star
#
# Injects an Authorization header into outgoing HTTP requests.
#
# Hook identity (RFC-001 §9.3):
#   register_hook("http", "on_request", fn, phase="post_pipeline")
#
# `phase="post_pipeline"` runs the hook after Intercept/Transform/Macro have
# settled, which is the right place for last-mile auth stamping: the value
# survives operator edits and resend/fuzz fan-out (RFC §9.3 D1).
#
# Plugin config (examples/config_with_plugins.json):
#   {
#     "path": "examples/plugins/add_auth_header.star",
#     "vars": { "auth_token": "Bearer eyJhbGc..." },
#     "on_error": "skip"
#   }

# Fall back to a placeholder when `vars.auth_token` is unset so the plugin
# loads even without configuration. `config` is a frozen dict supplied by
# the engine (see internal/pluginv2/modules.go).
DEFAULT_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example"
AUTH_TOKEN = config["auth_token"] if "auth_token" in config else DEFAULT_TOKEN

def stamp_auth(msg, ctx):
    """Replace any pre-existing Authorization header with the configured token."""
    # delete_first removes only the first match (case-insensitive); repeat
    # to scrub duplicates if needed. append preserves wire order.
    msg["headers"].delete_first("Authorization")
    msg["headers"].append("Authorization", AUTH_TOKEN)
    return None  # CONTINUE

register_hook("http", "on_request", stamp_auth, phase="post_pipeline")
