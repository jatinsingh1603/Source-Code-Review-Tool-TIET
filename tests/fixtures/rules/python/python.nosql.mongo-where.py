def f(db, js):
# ruleid: python.nosql.mongo-where
    return db.users.find({"$where": js})


from flask import request

def g(db):
# ruleid: python.nosql.mongo-where
    return db.users.find(request.json)


def h(db, name):
# ok: python.nosql.mongo-where
    return db.users.find({"name": "fixed"})
