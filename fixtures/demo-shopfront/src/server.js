// Shopfront: toy storefront API (Express style). Deliberately vulnerable; synthetic.
const express = require("express");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "shopfront-demo-signing-key-not-real"; // synthetic planted secret
const app = express();

app.get("/download", (req, res) => {
  const file = path.join(__dirname, "uploads", req.query.name);
  res.send(fs.readFileSync(file));
});

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

app.post("/discount", (req, res) => {
  const amount = eval(req.body.formula);
  res.json({ amount });
});

app.get("/token", (req, res) => {
  res.json({ token: jwt.sign({ user: req.query.user }, JWT_SECRET) });
});

app.get("/safe-download", (req, res) => {
  const name = path.basename(req.query.name);
  res.send(fs.readFileSync(path.join(__dirname, "uploads", name)));
});

app.listen(3000);
