from flask import redirect, request


def go():
# ruleid: python.redirect.open-redirect
    return redirect(request.args["next"])


def home():
# ok: python.redirect.open-redirect
    return redirect("/home")
