const crypto = require("crypto");


function a(p) {
// ruleid: javascript.crypto.weak-hash
  return crypto.createHash("md5").update(p).digest("hex");
}


function b(p) {
// ok: javascript.crypto.weak-hash
  return crypto.createHash("sha256").update(p).digest("hex");
}
