def find(owner, cur):
# ruleid: python.sqli.cursor-execute-concat
    cur.execute("SELECT * FROM accounts WHERE owner = '" + owner + "'")


def by_id(cur, account_id):
# ruleid: python.sqli.cursor-execute-concat
    cur.execute("SELECT * FROM t WHERE id = '%s'" % account_id)


def by_name(cur, name):
# ruleid: python.sqli.cursor-execute-concat
    cur.execute(f"SELECT * FROM t WHERE n = '{name}'")


def find_safe(owner, cur):
# ok: python.sqli.cursor-execute-concat
    cur.execute("SELECT * FROM accounts WHERE owner = ?", (owner,))


def constant(cur):
# ok: python.sqli.cursor-execute-concat
    cur.execute("SELECT 1 FROM " + "accounts")
