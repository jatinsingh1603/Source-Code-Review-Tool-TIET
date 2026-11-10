const fs = require("fs");

function read(name) {
  const base = "/srv/";
  return fs.readFileSync(base + name);
}
