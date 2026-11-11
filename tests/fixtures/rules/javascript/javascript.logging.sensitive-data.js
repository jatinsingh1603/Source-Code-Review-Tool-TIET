function a(password) {
// ruleid: javascript.logging.sensitive-data
  console.log("login", password);
}


function b(userId) {
// ok: javascript.logging.sensitive-data
  console.log("login", userId);
}
