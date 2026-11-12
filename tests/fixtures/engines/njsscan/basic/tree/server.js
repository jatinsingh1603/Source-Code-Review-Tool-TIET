const express = require("express");
const mysql = require("mysql");
const cp = require("child_process");
const app = express();
const connection = mysql.createConnection({host: "localhost"});
app.get("/", (req, res) => {
  connection.query("select * from t where a=" + req.query.a, function (e, r) { res.send(r); });
  cp.exec("ls " + req.query.dir);
  eval(req.query.code);
  res.send("<p>" + req.query.name + "</p>");
});
