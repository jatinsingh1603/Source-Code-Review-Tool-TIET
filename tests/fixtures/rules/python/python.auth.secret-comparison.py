def check(supplied, stored_token):
# ruleid: python.auth.secret-comparison
    if supplied == stored_token:
        return True


def check_ok(supplied):
# ok: python.auth.secret-comparison
    if supplied == "":
        return False
