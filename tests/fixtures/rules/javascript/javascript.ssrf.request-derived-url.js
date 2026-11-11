const axios = require("axios");


function a(req) {
// ruleid: javascript.ssrf.request-derived-url
  return axios.get(req.query.url);
}


function b() {
// ok: javascript.ssrf.request-derived-url
  return axios.get("https://api.example.com/rates");
}


function c(url, allowed) {
  if (!allowed.includes(new URL(url).hostname)) throw new Error("no");
// ok: javascript.ssrf.request-derived-url
  return axios.get(url);
}
