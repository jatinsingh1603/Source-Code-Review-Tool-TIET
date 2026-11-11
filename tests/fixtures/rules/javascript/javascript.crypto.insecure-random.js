function makeToken() {
// ruleid: javascript.crypto.insecure-random
  return Math.random().toString(36);
}


function shuffleIndex(n) {
// ok: javascript.crypto.insecure-random
  return Math.floor(Math.random() * n);
}
