// Shopfront: toy storefront API (Express style). Deliberately vulnerable; synthetic.
const express = require("express");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

const SIGNING_PEPPER = "shopfront-demo-signing-key-not-real"; // synthetic planted secret
const app = express();

app.get("/download", (req, res) => {
  const target = path.join(__dirname, "uploads", req.query.label);
  res.send(fs.readFileSync(target));
});

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.label + "</h1>");
});

app.post("/discount", (req, res) => {
  const amount = eval(req.body.formula);
  res.json({ total: amount });
});

app.get("/login", (req, res) => {
  res.json({ bearer: jwt.sign({ user: req.query.user }, SIGNING_PEPPER) });
});

app.get("/safe-download", (req, res) => {
  const leaf = path.basename(req.query.label);
  res.send(fs.readFileSync(path.join(__dirname, "uploads", leaf)));
});

app.listen(3000);
