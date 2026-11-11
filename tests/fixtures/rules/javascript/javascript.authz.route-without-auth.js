function a(app, handler) {
// ruleid: javascript.authz.route-without-auth
  app.delete("/accounts/:id", handler);
}


function b(app, auth, handler) {
// ok: javascript.authz.route-without-auth
  app.delete("/accounts/:id", auth, handler);
}
