def f(name):
# ruleid: python.sqli.raw-query
    return Account.objects.raw("SELECT * FROM a WHERE n = '%s'" % name)


def g(name):
# ok: python.sqli.raw-query
    return Account.objects.raw("SELECT * FROM a WHERE n = %s", [name])
