function a(libxml, text) {
// ruleid: javascript.xxe.libxml-noent
  return libxml.parseXml(text, { noent: true });
}


function b(libxml, text) {
// ok: javascript.xxe.libxml-noent
  return libxml.parseXml(text, { noent: false });
}
