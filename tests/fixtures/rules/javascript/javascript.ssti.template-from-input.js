const ejs = require("ejs");


function a(req) {
// ruleid: javascript.ssti.template-from-input
  return ejs.render("<h1>" + req.query.t + "</h1>");
}


function b(name) {
// ok: javascript.ssti.template-from-input
  return ejs.render("<h1><%= name %></h1>", { name });
}
