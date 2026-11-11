function a(Account, req) {
// ruleid: javascript.mass-assignment.body-splat
  return Account.create(req.body);
}


function b(Account, req) {
// ok: javascript.mass-assignment.body-splat
  return Account.create({ name: req.body.name });
}
