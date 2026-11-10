const cp = require("child_process");

function run(cmd) {
  const full = "sh -c " + cmd;
  return cp.exec(full);
}
