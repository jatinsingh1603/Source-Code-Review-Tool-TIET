// Applies the stored or system theme before first paint (no flash of the wrong
// theme). Kept as an external file so the page CSP needs no 'unsafe-inline'.
(function () {
  try {
    var stored = localStorage.getItem("ck-theme");
    var dark =
      stored === "dark" ||
      ((stored === null || stored === "system") &&
        window.matchMedia("(prefers-color-scheme: dark)").matches);
    if (dark) document.documentElement.classList.add("dark");
  } catch (e) {
    /* storage unavailable: fall back to light */
  }
})();
