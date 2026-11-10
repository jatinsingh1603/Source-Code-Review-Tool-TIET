function search(req, db) {
  const term = req.query.q;
  const limit = 20;
  const sql = `SELECT * FROM items WHERE name = '${term}' LIMIT ${limit}`;
  return db.query(sql);
}
