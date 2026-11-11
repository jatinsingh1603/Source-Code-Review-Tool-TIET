const escapeHtml = require("escape-html");


function a(req, res) {
// ruleid: javascript.xss.response-html-from-input
  res.send("<h1>" + req.query.name + "</h1>");
}


function b(res, name) {
// ruleid: javascript.xss.response-html-from-input
  res.send(`<p>${name}</p>`);
}


function c(res) {
// ok: javascript.xss.response-html-from-input
  res.send("<h1>Hello</h1>");
}


function d(res, name) {
// ok: javascript.xss.response-html-from-input
  res.send("<p>" + escapeHtml(name) + "</p>");
}
