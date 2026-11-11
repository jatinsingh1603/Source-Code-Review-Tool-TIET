const vm = require("vm");


function a(code) {
// ruleid: javascript.injection.eval
  return eval("(" + code + ")");
}


function b(code) {
// ruleid: javascript.injection.eval
  return vm.runInNewContext(code);
}


function c(text) {
// ok: javascript.injection.eval
  return JSON.parse(text);
}


function d() {
// ok: javascript.injection.eval
  return eval("1 + 1");
}
