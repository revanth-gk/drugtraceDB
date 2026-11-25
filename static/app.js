// DrugTrace UI behaviour. Loaded as an external file so the Content-Security-
// Policy can forbid inline scripts. Everything here is a convenience only:
// the server (and MySQL constraints) remain the source of truth.
(function () {
  "use strict";

  // ---- Theme toggle ------------------------------------------------------
  const root = document.documentElement;
  function storedTheme() {
    try { return localStorage.getItem("dt-theme"); } catch (e) { return null; }
  }
  function applyTheme(theme) {
    if (theme === "light" || theme === "dark") root.setAttribute("data-theme", theme);
    else root.removeAttribute("data-theme");
  }
  applyTheme(storedTheme());
  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const dark = root.getAttribute("data-theme") === "dark" ||
        (!root.getAttribute("data-theme") && window.matchMedia("(prefers-color-scheme: dark)").matches);
      const next = dark ? "light" : "dark";
      applyTheme(next);
      try { localStorage.setItem("dt-theme", next); } catch (e) { /* private mode */ }
    });
  });

  // ---- Mobile nav --------------------------------------------------------
  const navToggle = document.querySelector("[data-nav-toggle]");
  if (navToggle) {
    navToggle.addEventListener("click", function () {
      const open = document.body.classList.toggle("nav-open");
      navToggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  // ---- User menu ---------------------------------------------------------
  document.addEventListener("click", function (event) {
    document.querySelectorAll("details.menu[open]").forEach(function (menu) {
      if (!menu.contains(event.target)) menu.removeAttribute("open");
    });
  });

  // ---- Flash messages ----------------------------------------------------
  document.querySelectorAll(".flash").forEach(function (flash) {
    const close = flash.querySelector(".flash-close");
    if (close) close.addEventListener("click", function () { flash.remove(); });
    if (flash.classList.contains("flash-success") || flash.classList.contains("flash-info")) {
      setTimeout(function () {
        flash.classList.add("flash-leaving");
        setTimeout(function () { flash.remove(); }, 300);
      }, 6000);
    }
  });

  // ---- Confirm before destructive submits --------------------------------
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) event.preventDefault();
    });
  });

  // ---- Show / hide password ----------------------------------------------
  document.querySelectorAll("[data-password-toggle]").forEach(function (btn) {
    const input = document.getElementById(btn.getAttribute("data-password-toggle"));
    if (!input) return;
    btn.addEventListener("click", function () {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.setAttribute("aria-pressed", show ? "true" : "false");
      btn.textContent = show ? "Hide" : "Show";
    });
  });

  // ---- Caps-lock hint ----------------------------------------------------
  document.querySelectorAll("input[type=password]").forEach(function (input) {
    const hint = document.querySelector('[data-capslock-for="' + input.id + '"]');
    if (!hint) return;
    function check(e) {
      hint.hidden = !(e.getModifierState && e.getModifierState("CapsLock"));
    }
    input.addEventListener("keyup", check);
    input.addEventListener("keydown", check);
    input.addEventListener("blur", function () { hint.hidden = true; });
  });

  // ---- Password policy checklist + strength meter ------------------------
  // Mirrors security.validate_password(); the server re-checks everything.
  function passwordChecks(pw, username, min, max) {
    return {
      length: pw.length >= min && pw.length <= max,
      lower: /[a-z]/.test(pw),
      upper: /[A-Z]/.test(pw),
      digit: /\d/.test(pw),
      symbol: /[^A-Za-z0-9\s]/.test(pw),
      username: !(username && username.length >= 3 && pw.toLowerCase().indexOf(username.toLowerCase()) !== -1),
    };
  }

  document.querySelectorAll("[data-password-policy]").forEach(function (wrap) {
    const input = document.getElementById(wrap.getAttribute("data-password-policy"));
    if (!input) return;
    const min = parseInt(wrap.getAttribute("data-min"), 10) || 12;
    const max = parseInt(wrap.getAttribute("data-max"), 10) || 64;
    const userSel = wrap.getAttribute("data-username-source");
    const userFixed = wrap.getAttribute("data-username") || "";
    const userInput = userSel ? document.querySelector(userSel) : null;
    const bar = wrap.querySelector(".meter-fill");
    const label = wrap.querySelector(".meter-label");
    const confirmSel = wrap.getAttribute("data-confirm-source");
    const confirmInput = confirmSel ? document.querySelector(confirmSel) : null;
    const matchHint = wrap.querySelector("[data-match-hint]");

    function update() {
      const pw = input.value;
      const username = userInput ? userInput.value.trim().toLowerCase() : userFixed;
      const checks = passwordChecks(pw, username, min, max);
      let met = 0;
      Object.keys(checks).forEach(function (key) {
        const item = wrap.querySelector('[data-rule="' + key + '"]');
        const ok = pw.length > 0 && checks[key];
        if (ok) met += 1;
        if (item) item.classList.toggle("ok", ok);
      });
      const total = Object.keys(checks).length;
      const allOk = met === total;
      // Bonus for length beyond the minimum once all rules pass.
      let score = pw.length ? met / total : 0;
      if (allOk) score = Math.min(1, 0.8 + (pw.length - min) * 0.04);
      const levels = ["Too weak", "Weak", "Fair", "Good", "Strong"];
      const level = !pw.length ? -1 : allOk ? (score >= 1 ? 4 : 3) : Math.min(2, Math.floor(score * 3));
      if (bar) {
        bar.style.width = (pw.length ? Math.max(8, score * 100) : 0) + "%";
        bar.setAttribute("data-level", String(level));
      }
      if (label) label.textContent = level < 0 ? "" : levels[level];
      input.setCustomValidity(pw.length && !allOk ? "Password does not meet the requirements." : "");

      if (confirmInput) {
        const mismatch = confirmInput.value.length > 0 && confirmInput.value !== pw;
        confirmInput.setCustomValidity(mismatch ? "Passwords do not match." : "");
        if (matchHint) matchHint.hidden = !mismatch;
      }
    }
    input.addEventListener("input", update);
    if (userInput) userInput.addEventListener("input", update);
    if (confirmInput) confirmInput.addEventListener("input", update);
    update();
  });

  // ---- Username live validation -----------------------------------------
  document.querySelectorAll("[data-username-input]").forEach(function (input) {
    const re = new RegExp(input.getAttribute("data-pattern"));
    const hint = document.getElementById(input.getAttribute("aria-describedby"));
    input.addEventListener("input", function () {
      const lowered = input.value.toLowerCase();
      if (lowered !== input.value) {
        const pos = input.selectionStart;
        input.value = lowered;
        input.setSelectionRange(pos, pos);
      }
      const ok = !input.value || (re.test(input.value) && input.value.length >= 3 && input.value.length <= 30);
      input.setCustomValidity(ok ? "" : "Use 3–30 lowercase letters, digits and single . _ - separators, starting with a letter.");
      if (hint) hint.classList.toggle("invalid", !ok);
    });
  });

  // ---- Movement form: enable only the facility fields the type allows ----
  const movementType = document.getElementById("movement_type");
  if (movementType) {
    const rules = {
      INITIAL_RECEIPT: { from: false, to: true },
      TRANSFER: { from: true, to: true },
      RETURN: { from: true, to: true },
      DAMAGE: { from: true, to: false },
      EXPIRY: { from: true, to: false },
    };
    const from = document.getElementById("from_facility_id");
    const to = document.getElementById("to_facility_id");
    const apply = function () {
      const rule = rules[movementType.value] || { from: true, to: true };
      if (from) from.disabled = !rule.from;
      if (to) to.disabled = !rule.to;
    };
    movementType.addEventListener("change", apply);
    apply();
  }
})();
