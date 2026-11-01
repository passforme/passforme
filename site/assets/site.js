// Language for every page: elements with data-lang="pt" or "en" show for
// their language only, and an image's alt text comes from data-alt-pt or
// data-alt-en. The choice is remembered; without one, the browser's
// language decides (Portuguese when it starts with "pt"). Pages that need
// to react (the guide's search) register with window.pfmLang.on(fn).
(function () {
  var root = document.documentElement;
  var listeners = [];
  var current = "pt";

  function setLang(lang) {
    current = lang;
    root.lang = lang === "pt" ? "pt-BR" : "en";
    document.querySelectorAll("[data-lang]").forEach(function (el) {
      el.hidden = el.getAttribute("data-lang") !== lang;
    });
    document.querySelectorAll(".langs button").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-set") === lang));
    });
    document.querySelectorAll("[data-alt-" + lang + "]").forEach(function (el) {
      el.alt = el.getAttribute("data-alt-" + lang);
    });
    var title = root.getAttribute(lang === "pt" ? "data-title-pt" : "data-title-en");
    if (title) document.title = title;
    try { localStorage.setItem("pfm-lang", lang); } catch (e) {}
    listeners.forEach(function (fn) { fn(lang); });
  }

  window.pfmLang = {
    on: function (fn) { listeners.push(fn); fn(current); },
    get current() { return current; }
  };

  document.querySelectorAll(".langs button").forEach(function (b) {
    b.addEventListener("click", function () { setLang(b.getAttribute("data-set")); });
  });
  var saved = null;
  try { saved = localStorage.getItem("pfm-lang"); } catch (e) {}
  var browser = (navigator.language || "pt").toLowerCase().indexOf("pt") === 0 ? "pt" : "en";
  setLang(saved === "pt" || saved === "en" ? saved : browser);
})();
