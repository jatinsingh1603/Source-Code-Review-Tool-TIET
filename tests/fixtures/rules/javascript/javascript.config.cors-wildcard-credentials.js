function a(cors) {
// ruleid: javascript.config.cors-wildcard-credentials
  return cors({ origin: "*", credentials: true });
}


function b(cors) {
// ok: javascript.config.cors-wildcard-credentials
  return cors({ origin: "https://app.example.com", credentials: true });
}
