import functools

from flask import Flask

app = Flask(__name__)


def audited(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


@app.route("/ping")
@audited
def ping_handler():
    return "ok"
