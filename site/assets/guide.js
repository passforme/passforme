// The guide: copy buttons and search. Language comes from site.js.
(function () {
  var copyLabel = { pt: ["Copiar", "Copiado", "Selecionado"], en: ["Copy", "Copied", "Selected"] };
  var placeholder = { pt: "ex.: cvv, totp, gerar, sessão", en: "e.g. cvv, totp, generate, session" };
  var input = document.getElementById("q");
  var current = "pt";

  // Copy buttons: the command without the trailing comment.
  document.querySelectorAll(".line").forEach(function (line) {
    var button = line.querySelector("button");
    var span = line.querySelector(".c");
    var lang = line.closest("[data-lang]").getAttribute("data-lang");
    button.addEventListener("click", function () {
      var text = span.cloneNode(true);
      text.querySelectorAll(".hash").forEach(function (h) { h.remove(); });
      var value = text.textContent.trim();
      function done() {
        button.textContent = copyLabel[lang][1];
        button.classList.add("done");
        setTimeout(function () { button.textContent = copyLabel[lang][0]; button.classList.remove("done"); }, 1500);
      }
      function fallback() {
        var range = document.createRange();
        range.selectNodeContents(span);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        button.textContent = copyLabel[lang][2];
      }
      try { navigator.clipboard.writeText(value).then(done, fallback); } catch (e) { fallback(); }
    });
  });

  // Search: within the visible language, hide cards and rows that miss a term.
  function norm(s) { return s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, ""); }
  function filter() {
    var wrap = document.querySelector('.wrap[data-lang="' + current + '"]');
    var terms = norm(input.value).split(/\s+/).filter(Boolean);
    var anyShown = false;
    wrap.querySelectorAll("main section").forEach(function (section) {
      var sectionShown = false;
      var sub = section.querySelector(".sub");
      var heading = norm(section.querySelector("h2").textContent + " " + (sub ? sub.textContent : ""));
      section.querySelectorAll(".cmd").forEach(function (card) {
        var h3 = card.querySelector("h3");
        var title = h3 ? norm(h3.textContent) : "";
        var cardText = norm(card.textContent) + " " + heading;
        var titleMatch = terms.length > 0 && terms.every(function (t) { return (title + " " + heading).indexOf(t) !== -1; });
        card.querySelectorAll("tr").forEach(function (row, i) {
          if (i === 0) { row.hidden = false; return; }
          var rowText = norm(row.textContent) + " " + title + " " + heading;
          var rowMatch = terms.every(function (t) { return rowText.indexOf(t) !== -1; });
          row.hidden = terms.length > 0 && !rowMatch && !titleMatch;
        });
        card.hidden = terms.length > 0 && !terms.every(function (t) { return cardText.indexOf(t) !== -1; });
        if (!card.hidden) sectionShown = true;
      });
      section.hidden = terms.length > 0 && !sectionShown;
      if (!section.hidden) anyShown = true;
    });
    wrap.querySelector(".empty").hidden = anyShown;
  }
  input.addEventListener("input", filter);

  window.pfmLang.on(function (lang) {
    current = lang;
    input.placeholder = placeholder[lang];
    filter();
  });
})();
