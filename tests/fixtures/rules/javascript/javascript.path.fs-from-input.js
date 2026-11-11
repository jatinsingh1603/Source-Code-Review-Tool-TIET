const fs = require("fs");
const path = require("path");


function a(name) {
// ruleid: javascript.path.fs-from-input
  return fs.readFileSync("/data/" + name);
}


function b(req) {
// ruleid: javascript.path.fs-from-input
  return fs.readFile(req.query.file, () => {});
}


function c() {
// ok: javascript.path.fs-from-input
  return fs.readFileSync("/data/report.txt");
}


function d(name) {
// ok: javascript.path.fs-from-input
  return fs.readFileSync("/data/" + path.basename(name));
}
