const jwt = require("jsonwebtoken");


function a(p) {
// ruleid: javascript.crypto.jwt-hardcoded-secret
  return jwt.sign(p, "changeme");
}


function b(p) {
// ok: javascript.crypto.jwt-hardcoded-secret
  return jwt.sign(p, process.env.JWT_KEY);
}
