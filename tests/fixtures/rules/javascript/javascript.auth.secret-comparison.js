function a(supplied, storedToken) {
// ruleid: javascript.auth.secret-comparison
  return supplied === storedToken;
}


function b(supplied) {
// ok: javascript.auth.secret-comparison
  return supplied === "";
}
