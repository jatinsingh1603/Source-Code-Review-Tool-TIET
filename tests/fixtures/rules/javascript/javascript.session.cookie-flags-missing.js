function a(res) {
// ruleid: javascript.session.cookie-flags-missing
  res.cookie("sid", "v", { secure: false });
}


function b(res) {
// ok: javascript.session.cookie-flags-missing
  res.cookie("sid", "v", { secure: true, httpOnly: true });
}
