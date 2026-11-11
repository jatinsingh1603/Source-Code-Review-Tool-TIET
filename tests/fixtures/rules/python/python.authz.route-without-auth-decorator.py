from flask import Flask

app = Flask(__name__)


def require_auth(f):
    return f


@app.route("/close", methods=["POST"])
# ruleid: python.authz.route-without-auth-decorator
def close_account():
    return "closed"


@app.route("/close_own", methods=["POST"])
@require_auth
# ok: python.authz.route-without-auth-decorator
def close_own():
    return "ok"


@app.route("/health")
# ok: python.authz.route-without-auth-decorator
def health():
    return "ok"
