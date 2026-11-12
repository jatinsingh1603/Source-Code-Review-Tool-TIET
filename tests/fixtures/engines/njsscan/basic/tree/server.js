const express = require("express");
const app = express();
app.get("/", (req, res) => {
  db.query("select * from t where a=" + req.query.a);
});
