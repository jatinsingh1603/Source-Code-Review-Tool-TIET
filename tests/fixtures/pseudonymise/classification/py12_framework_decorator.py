from flask import Flask

app = Flask(__name__)


@app.route("/balance/<account_id>")
def balance(account_id):
    return str(account_id)
