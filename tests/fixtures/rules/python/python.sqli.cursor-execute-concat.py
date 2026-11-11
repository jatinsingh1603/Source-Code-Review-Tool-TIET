def find(owner, cur):
    # ruleid: python.sqli.cursor-execute-concat
    cur.execute("SELECT * FROM accounts WHERE owner = '" + owner + "'")
    # ok: python.sqli.cursor-execute-concat
    cur.execute("SELECT * FROM accounts WHERE owner = ?", (owner,))


def constant(cur):
    # ok: python.sqli.cursor-execute-concat
    cur.execute("SELECT 1 FROM " + "accounts")
