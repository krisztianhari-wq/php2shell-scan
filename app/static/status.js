// Státusz oldal: /api/stats → csempék + táblák. A ?token= (ha van) továbbmegy az API-nak.
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
document.getElementById("themebtn").addEventListener("click", () => {
  const cur = document.documentElement.dataset.theme === "light" ? "light" : "dark";
  const next = cur === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("theme", next); } catch (e) {}
});

function tile(label, val, cls) {
  return `<div class="stat ${cls || ""}"><b>${esc(label)}</b><span>${esc(val)}</span></div>`;
}
function rows(list, cols) {
  if (!list || !list.length) return `<p class="sub">nincs adat</p>`;
  const head = `<tr>${cols.map((c) => `<th${c.num ? ' class="num"' : ""}>${esc(c.h)}</th>`).join("")}</tr>`;
  const body = list.map((r) =>
    `<tr>${cols.map((c) => `<td${c.num ? ' class="num"' : ""}>${esc(c.get(r))}</td>`).join("")}</tr>`).join("");
  return `<table class="table">${head}${body}</table>`;
}

async function load() {
  const token = new URLSearchParams(location.search).get("token") || "";
  const note = document.getElementById("note");
  let data;
  try {
    const res = await fetch("/api/stats" + (token ? "?token=" + encodeURIComponent(token) : ""),
      { headers: token ? { "X-Status-Token": token } : {} });
    if (res.status === 401) {
      note.textContent = "Nincs jogosultság a statisztikához (token/passkey szükséges).";
      note.classList.add("err"); note.hidden = false; return;
    }
    data = await res.json();
  } catch (e) {
    note.textContent = "A statisztika nem tölthető be."; note.classList.add("err"); note.hidden = false; return;
  }

  if (!data.enabled) {
    note.textContent = "A használati naplózás ki van kapcsolva (PHP2SHELL_LOG=off).";
    note.hidden = false;
  }

  const hitRate = data.total ? Math.round((data.with_findings / data.total) * 100) : 0;
  document.getElementById("tiles").innerHTML =
    tile("Összes vizsgálat", data.total, "accent") +
    tile("Ma", data.today) +
    tile("Találatos", data.with_findings + " (" + hitRate + "%)", data.with_findings ? "bad" : "good") +
    tile("Bővített (extended)", data.extended) +
    tile("Feloldatlan", data.unresolved) +
    tile("Kritikus jelzés", (data.sev && data.sev.critical) || 0, "bad");

  document.getElementById("targets").innerHTML = rows(data.top_targets,
    [{ h: "Célpont", get: (r) => r.target }, { h: "db", num: true, get: (r) => r.n }]);
  document.getElementById("ips").innerHTML = rows(data.top_ips,
    [{ h: "Vizsgáló IP", get: (r) => r.ip }, { h: "db", num: true, get: (r) => r.n }]);
  document.getElementById("recent").innerHTML = rows(data.recent,
    [{ h: "Időpont (UTC)", get: (r) => (r.ts || "").replace("T", " ").replace("+00:00", "") },
     { h: "IP", get: (r) => r.ip },
     { h: "Célpont", get: (r) => r.target },
     { h: "Ext", get: (r) => (r.extended ? "✓" : "") },
     { h: "Talál.", num: true, get: (r) => r.n }]);
}
load();
