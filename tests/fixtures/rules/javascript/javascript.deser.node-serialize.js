function a(serialize, blob) {
// ruleid: javascript.deser.node-serialize
  return serialize.unserialize(blob);
}


function b(text) {
// ok: javascript.deser.node-serialize
  return JSON.parse(text);
}
