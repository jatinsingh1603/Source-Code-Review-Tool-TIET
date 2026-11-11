function a(https) {
// ruleid: javascript.crypto.tls-verify-disabled
  return https.request({ rejectUnauthorized: false });
}


// ruleid: javascript.crypto.tls-verify-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";


function b(https) {
// ok: javascript.crypto.tls-verify-disabled
  return https.request({ rejectUnauthorized: true });
}
