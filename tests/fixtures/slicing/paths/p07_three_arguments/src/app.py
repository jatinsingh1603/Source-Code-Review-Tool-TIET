def build(req, config):
    table = config.table
    column = req.args["column"]
    limit = 10
    cur.execute("SELECT " + column + " FROM " + table + " LIMIT %s", (limit,))
