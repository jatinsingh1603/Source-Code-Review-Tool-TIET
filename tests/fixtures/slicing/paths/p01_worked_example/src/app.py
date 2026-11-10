def transfer(req):
    amount = req.json["amount"]
    note = req.json["note"]
    audit(note)
    if not is_admin(req.user):
        raise Forbidden()
    cur.execute("UPDATE accounts SET bal = bal - " + amount)
    return "ok"
