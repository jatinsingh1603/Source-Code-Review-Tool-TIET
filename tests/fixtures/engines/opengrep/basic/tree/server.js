// Synthetic sample for the engine conformance cases. Not real code.
const child = require("child_process");

function handler(req, res) {
  const name = req.query.name;
  child.exec("ls " + name);
  const pattern = new RegExp(name);
  eval(name);
  document.getElementById("greeting").innerHTML = name;
  return pattern;
}

module.exports = handler;
