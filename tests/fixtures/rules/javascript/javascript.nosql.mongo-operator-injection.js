function a(users, req) {
// ruleid: javascript.nosql.mongo-operator-injection
  return users.findOne(req.body);
}


function b(users, req) {
// ok: javascript.nosql.mongo-operator-injection
  return users.findOne({ name: String(req.body.name) });
}
