def serve(app):
# ruleid: python.config.debug-enabled
    app.run(host="0.0.0.0", debug=True)


# ruleid: python.config.debug-enabled
DEBUG = True


def serve_safe(app):
# ok: python.config.debug-enabled
    app.run(host="127.0.0.1")
