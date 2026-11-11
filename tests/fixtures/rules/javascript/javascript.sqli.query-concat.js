function a(db, id) {
// ruleid: javascript.sqli.query-concat
  return db.query("SELECT * FROM t WHERE id = " + id);
}


function b(db, id) {
// ruleid: javascript.sqli.query-concat
  return db.query(`SELECT * FROM t WHERE id = ${id}`);
}


function c(db, id) {
// ok: javascript.sqli.query-concat
  return db.query("SELECT * FROM t WHERE id = ?", [id]);
}
