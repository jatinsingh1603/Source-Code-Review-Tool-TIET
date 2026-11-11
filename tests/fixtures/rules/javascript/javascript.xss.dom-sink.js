function a(el, name) {
// ruleid: javascript.xss.dom-sink
  el.innerHTML = "<b>" + name + "</b>";
}


function b(el) {
// ruleid: javascript.xss.dom-sink
  el.innerHTML = location.hash;
}


function c(el, name) {
// ok: javascript.xss.dom-sink
  el.textContent = name;
}


function d(el) {
// ok: javascript.xss.dom-sink
  el.innerHTML = "<b>fixed</b>";
}
