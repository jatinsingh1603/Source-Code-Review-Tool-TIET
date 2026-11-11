const jwt = require("jsonwebtoken");


function a(t) {
// ruleid: javascript.crypto.jwt-verification-disabled
  return jwt.decode(t);
}


function b(t, key) {
// ok: javascript.crypto.jwt-verification-disabled
  return jwt.verify(t, key, { algorithms: ["HS256"] });
}
