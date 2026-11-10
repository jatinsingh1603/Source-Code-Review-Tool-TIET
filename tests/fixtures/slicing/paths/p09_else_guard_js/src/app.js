function remove(req, db) {
  const ident = req.query.id;
  if (req.user.admin) {
    log("admin");
  } else {
    return null;
  }
  db.query("DELETE FROM t WHERE id = " + ident);
  return true;
}
