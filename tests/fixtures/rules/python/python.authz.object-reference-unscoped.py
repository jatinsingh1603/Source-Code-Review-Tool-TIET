from flask import Flask, g

app = Flask(__name__)


@app.route("/accounts/<account_id>")
# ruleid: python.authz.object-reference-unscoped
def show(account_id):
    return get_account(account_id)


@app.route("/me/accounts/<account_id>")
# ok: python.authz.object-reference-unscoped
def show_own(account_id):
    return get_account(account_id, owner=g.user)
