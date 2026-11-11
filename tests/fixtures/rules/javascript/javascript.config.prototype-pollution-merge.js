function a(_, cfg, req) {
// ruleid: javascript.config.prototype-pollution-merge
  _.merge(cfg, req.body);
}


function b(_, cfg) {
// ok: javascript.config.prototype-pollution-merge
  _.merge(cfg, { limit: 10 });
}
