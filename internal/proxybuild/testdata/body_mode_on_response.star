# USK-1409 body-mode predicate fixture: an http.on_response hook that
# observes the response and changes nothing.
def on_response(msg, ctx):
    return None

register_hook("http", "on_response", on_response, phase="post_pipeline")
