// Runs in <head> before first paint so a saved theme never flashes.
(function () {
  try {
    var t = localStorage.getItem("dt-theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) { /* storage unavailable */ }
})();
