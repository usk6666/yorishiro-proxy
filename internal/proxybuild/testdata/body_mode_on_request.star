# USK-1409 body-mode predicate fixture: an http.on_request hook only.
def on_request(msg, ctx):
    return None

register_hook("http", "on_request", on_request, phase="pre_pipeline")
