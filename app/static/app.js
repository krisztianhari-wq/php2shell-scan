// php2shell-scan – fő oldal logikája. Egy domain → POST /api/scan → eredmény.
let LANG = currentLang();

function t(key) {
  const parts = key.split(".");
  let v = I18N[LANG];
  for (const p of parts) v = v && v[p];
  return v == null ? key : v;
}
function fl(f) { return LANG === "en" ? (f.title_en || f.title) : f.title; }
function fe(f) { return LANG === "en" ? (f.evidence_en || f.evidence) : f.evidence; }

function applyI18n() {
  document.documentElement.lang = LANG;
  document.querySelectorAll("[data-t]").forEach((el) => { el.textContent = t(el.dataset.t); });
  document.querySelectorAll("[data-ph]").forEach((el) => { el.placeholder = t(el.dataset.ph); });
  document.getElementById("foot").textContent = t("not_exploit") + " " + t("footer_note");
  document.querySelectorAll("#lang button").forEach((b) => b.classList.toggle("on", b.dataset.lang === LANG));
  const r = window.__lastResult;
  if (r) renderResult(r);
}

function setLang(l) {
  LANG = l;
  try { localStorage.setItem("lang", l); } catch (e) {}
  applyI18n();
}

function toggleTheme() {
  const cur = document.documentElement.dataset.theme === "light" ? "light" : "dark";
  const next = cur === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("theme", next); } catch (e) {}
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function renderResult(r) {
  window.__lastResult = r;
  const box = document.getElementById("result");
  const hit = (r.findings || []).some((f) => f.severity === "critical" || f.severity === "high");
  const hdr = [];
  hdr.push(`<div class="rhead"><h2>${esc(r.host)}</h2>` +
    `<span class="verdict ${hit ? "hit" : "clean"}">${hit ? "⚠ " + t("findings") : "✓ " + t("result_clean")}</span></div>`);

  const meta = [];
  if (r.ips && r.ips.length) meta.push(`<span>${t("resolved_to")}: <b>${esc(r.ips.join(", "))}</b></span>`);
  if (r.server) meta.push(`<span>${t("server")}: <b>${esc(r.server)}</b></span>`);
  if (r.powered_by) meta.push(`<span>${t("powered_by")}: <b>${esc(r.powered_by)}</b></span>`);
  if (!r.server && !r.powered_by) meta.push(`<span>${t("no_header")}</span>`);
  if (r.ports && r.ports.length)
    meta.push(`<span>${t("ports")}: <b>${esc(r.ports.map((p) => p.port + "/" + p.scheme).join(" "))}</b></span>`);
  hdr.push(`<div class="meta">${meta.join("")}</div>`);

  let body;
  if (!r.findings || !r.findings.length) {
    body = `<div class="cleanbox">${t("result_clean_sub")}</div>`;
  } else {
    const items = r.findings.map((f) => {
      const sev = f.severity || "info";
      const method = f.method === "fingerprint" ? t("method_fingerprint") : t("method_version");
      return `<div class="find ${esc(sev)}"><div class="ftop">` +
        `<span class="badge ${esc(sev)}">${esc(t("sev." + sev))}</span>` +
        `<span class="ftitle">${esc(fl(f))}</span>` +
        `<span class="tag">${esc(method)}</span></div>` +
        `<div class="cve">${esc(f.cve)}</div>` +
        `<div class="ev">${esc(fe(f))}</div></div>`;
    });
    body = `<div class="finds">${items.join("")}</div>`;
  }

  box.innerHTML = `<div class="card">${hdr.join("")}${body}</div>`;
  box.hidden = false;
}

function showError(key) {
  const el = document.getElementById("error");
  el.textContent = t(key);
  el.hidden = false;
}

async function runScan(ev) {
  ev.preventDefault();
  const target = document.getElementById("target").value.trim();
  if (!target) return;
  const extended = document.getElementById("extended").checked;
  const go = document.getElementById("go");
  document.getElementById("error").hidden = true;
  document.getElementById("result").hidden = true;
  window.__lastResult = null;
  document.getElementById("statustarget").textContent = target;
  document.getElementById("status").hidden = false;
  go.disabled = true;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, extended }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.error) {
      showError("err_" + (data.error || "generic"));
    } else if (!data.resolved) {
      showError("err_" + (data.reason || "no_public_ip"));
    } else {
      renderResult(data);
    }
  } catch (e) {
    showError("err_generic");
  } finally {
    document.getElementById("status").hidden = true;
    go.disabled = false;
  }
}

document.getElementById("form").addEventListener("submit", runScan);
document.getElementById("themebtn").addEventListener("click", toggleTheme);
document.querySelectorAll("#lang button").forEach((b) =>
  b.addEventListener("click", () => setLang(b.dataset.lang)));
applyI18n();
