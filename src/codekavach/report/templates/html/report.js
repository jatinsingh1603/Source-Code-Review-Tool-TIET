/* CodeKavach report interactions. Dependency-free; reads data attributes and writes only
   classes, attributes, textContent and the URL fragment. No dynamic markup, no evaluation. */
(function () {
  "use strict";
  var KEY = "codekavach.report.theme";
  var root = document.documentElement;
  function store(get, value) {
    try {
      if (get) { return window.localStorage.getItem(KEY); }
      window.localStorage.setItem(KEY, value);
    } catch (e) { /* storage may be unavailable for a file: URL */ }
    return null;
  }
  var saved = store(true);
  if (saved === "dark" || saved === "light") { root.setAttribute("data-theme", saved); }
  function byId(id) { return document.getElementById(id); }
  var themeBtn = byId("ck-theme");
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var dark = root.getAttribute("data-theme") === "dark" ||
        (!root.getAttribute("data-theme") && window.matchMedia &&
         window.matchMedia("(prefers-color-scheme: dark)").matches);
      var next = dark ? "light" : "dark";
      root.setAttribute("data-theme", next);
      store(false, next);
    });
  }
  var printBtn = byId("ck-print");
  if (printBtn) { printBtn.addEventListener("click", function () { window.print(); }); }
  var list = byId("ck-list");
  var items = list ? Array.prototype.slice.call(list.querySelectorAll("details.finding")) : [];
  var expand = byId("ck-expand");
  if (expand) {
    expand.addEventListener("click", function () {
      var open = expand.textContent === "Expand all";
      items.forEach(function (d) { d.open = open; });
      expand.textContent = open ? "Collapse all" : "Expand all";
    });
  }
  window.addEventListener("beforeprint", function () { items.forEach(function (d) { d.open = true; }); });
  var q = byId("ck-q"), sev = byId("ck-sev"), status = byId("ck-status"), cwe = byId("ck-cwe"),
      sort = byId("ck-sort"), count = byId("ck-count"), clear = byId("ck-clear");
  if (!list || !q) { openFromHash(); return; }
  function state() {
    return { q: q.value.trim().toLowerCase(), sev: sev.value, status: status.value,
             cwe: cwe.value, sort: sort.value };
  }
  function writeHash(s) {
    var parts = [];
    ["q", "sev", "status", "cwe", "sort"].forEach(function (k) {
      if (s[k] && !(k === "sort" && s[k] === "sev")) { parts.push(k + "=" + encodeURIComponent(s[k])); }
    });
    var hash = parts.length ? "#filter:" + parts.join("&") : "";
    if (window.history && window.history.replaceState) {
      window.history.replaceState(null, "", hash || window.location.pathname + window.location.search);
    }
  }
  function readHash() {
    var h = window.location.hash;
    if (h.indexOf("#filter:") !== 0) { return false; }
    h.slice(8).split("&").forEach(function (pair) {
      var kv = pair.split("="), v = decodeURIComponent(kv[1] || "");
      if (kv[0] === "q") { q.value = v; } else if (kv[0] === "sev") { sev.value = v; }
      else if (kv[0] === "status") { status.value = v; } else if (kv[0] === "cwe") { cwe.value = v; }
      else if (kv[0] === "sort") { sort.value = v; }
    });
    return true;
  }
  function key(d, how) {
    if (how === "id") { return d.id; }
    if (how === "cwe") { return (d.dataset.cwe || "~") + d.id; }
    if (how === "file") { return d.dataset.file + ":" + ("000000" + d.dataset.line).slice(-6); }
    return (9 - Number(d.dataset.rank)) + d.id;
  }
  function apply(updateHash) {
    var s = state(), shown = 0;
    items.forEach(function (d) {
      var ok = (!s.sev || d.dataset.severity === s.sev) &&
               (!s.status || d.dataset.status === s.status) &&
               (!s.cwe || (" " + d.dataset.cwe.replace(/,/g, " ") + " ").indexOf(" " + s.cwe + " ") >= 0) &&
               (!s.q || d.dataset.search.indexOf(s.q) >= 0);
      d.classList.toggle("hidden", !ok);
      if (ok) { shown += 1; }
    });
    items.slice().sort(function (a, b) {
      var ka = key(a, s.sort), kb = key(b, s.sort);
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    }).forEach(function (d) { list.appendChild(d); });
    count.textContent = shown + " of " + items.length + " findings";
    if (updateHash) { writeHash(s); }
  }
  [q, sev, status, cwe, sort].forEach(function (el) {
    el.addEventListener(el === q ? "input" : "change", function () { apply(true); });
  });
  clear.addEventListener("click", function () {
    q.value = ""; sev.value = ""; status.value = ""; cwe.value = ""; sort.value = "sev";
    apply(true);
  });
  function openFromHash() {
    var h = window.location.hash.slice(1);
    if (!h || h.indexOf("filter:") === 0) { return; }
    var el = document.getElementById(h);
    if (el && el.tagName === "DETAILS") { el.open = true; }
  }
  document.querySelectorAll("#summary-table a").forEach(function (a) {
    a.addEventListener("click", function () {
      var el = document.getElementById(a.getAttribute("href").slice(1));
      if (el && el.tagName === "DETAILS") { el.open = true; }
    });
  });
  document.querySelectorAll("ol.flow li").forEach(function (li) {
    li.addEventListener("click", function () {
      var body = li.closest(".fbody");
      if (!body) { return; }
      body.querySelectorAll(".ln.focus").forEach(function (n) { n.classList.remove("focus"); });
      body.querySelectorAll(".ln").forEach(function (n) {
        var no = n.querySelector(".no");
        if (no && no.textContent === li.dataset.line) { n.classList.add("focus"); n.scrollIntoView({ block: "center" }); }
      });
    });
  });
  readHash();
  apply(false);
  openFromHash();
  window.addEventListener("hashchange", openFromHash);
}());
