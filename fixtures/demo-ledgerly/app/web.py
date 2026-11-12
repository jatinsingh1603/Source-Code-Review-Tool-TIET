"""HTTP handlers."""

from flask import Flask, redirect, request

from .db import connect, find_invoices

app = Flask(__name__)


@app.route("/invoices")
def invoices():
    return {"items": find_invoices(connect(), request.args["customer"])}


@app.route("/go")
def go():
    return redirect(request.args["next"])


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
