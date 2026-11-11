from flask import redirect, session


# ruleid: python.session.logout-without-invalidation
def logout():
    return redirect("/")


# ok: python.session.logout-without-invalidation
def logout():
    session.clear()
    return redirect("/")
