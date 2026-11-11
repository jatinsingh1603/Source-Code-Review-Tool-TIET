const cp = require("child_process");
const quote = require("shell-quote").quote;


function a(name) {
// ruleid: javascript.injection.child-process-exec
  cp.exec("ping " + name);
}


function b(req) {
// ruleid: javascript.injection.child-process-exec
  cp.execSync(req.query.cmd);
}


function c() {
// ok: javascript.injection.child-process-exec
  cp.exec("uptime");
}


function d(name) {
// ok: javascript.injection.child-process-exec
  cp.execFile("ping", [name]);
}
