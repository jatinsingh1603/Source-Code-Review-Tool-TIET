function a(req, res) {
// ruleid: javascript.redirect.open-redirect
  res.redirect(req.query.next);
}


function b(res) {
// ok: javascript.redirect.open-redirect
  res.redirect("/home");
}
