// Státusz oldal: /api/stats → csempék + táblák + teljes vizsgálati napló (szűrhető).
// A "Kritikus jelzés" csempe a kritikus találatos vizsgálatokra szűr. HU/EN. ?token= továbbmegy az API-nak.
const STATUS_I18N = {
  hu: {
    status: "Státusz", back_scanner: "← szkenner",
    eyebrow: "Használati statisztika",
    lead: "A háttér-használati naplóból – ki (vizsgáló IP) mely célpontot vizsgálta. Üzemeltetői nézet, nem publikus.",
    t_total: "Összes vizsgálat", t_today: "Ma", t_hits: "Találatos", t_ext: "Bővített",
    t_unres: "Feloldatlan", t_crit: "Kritikus jelzés",
    top_targets: "Top célpontok", top_ips: "Top vizsgáló IP-k", all_scans: "Összes vizsgálat",
    c_target: "Célpont", c_ip: "Vizsgáló IP", c_count: "db", c_time: "Időpont (UTC)",
    c_ext: "Ext", c_findings: "Találatok",
    f_all: "Mind", f_hits: "Találatos", f_critical: "Kritikus",
    filter_ph: "Szűrés domainre vagy IP-re…",
    inferred: "Következtetett: alap (nem bővített) módban csak a php2shell páros futhat, így a kritikus találat biztosan ez. A régi bejegyzésnél a konkrét CVE még nem volt naplózva.",
    none: "nincs adat", no_find: "–", scans_n: (n, t) => `${n} / ${t} vizsgálat`,
    no_auth: "Nincs jogosultság a statisztikához (token/passkey szükséges).",
    load_err: "A statisztika nem tölthető be.",
    disabled: "A használati naplózás ki van kapcsolva (PHP2SHELL_LOG=off).",
  },
  en: {
    status: "Status", back_scanner: "← scanner",
    eyebrow: "Usage statistics",
    lead: "From the background usage log – who (scanner IP) scanned which target. Operator view, not public.",
    t_total: "Total scans", t_today: "Today", t_hits: "With findings", t_ext: "Extended",
    t_unres: "Unresolved", t_crit: "Critical flags",
    top_targets: "Top targets", top_ips: "Top scanner IPs", all_scans: "All scans",
    c_target: "Target", c_ip: "Scanner IP", c_count: "n", c_time: "Time (UTC)",
    c_ext: "Ext", c_findings: "Findings",
    f_all: "All", f_hits: "With findings", f_critical: "Critical",
    filter_ph: "Filter by domain or IP…",
    inferred: "Inferred: in default (non-extended) mode only the php2shell pair can run, so a critical hit is certainly this one. The old entry did not record the exact CVE yet.",
    none: "no data", no_find: "–", scans_n: (n, t) => `${n} / ${t} scans`,
    no_auth: "Not authorized for statistics (token/passkey required).",
    load_err: "Could not load statistics.",
    disabled: "Usage logging is disabled (PHP2SHELL_LOG=off).",
  },
};

let LANG = (() => { try { return localStorage.getItem("lang") === "en" ? "en" : "hu"; } catch (e) { return "hu"; } })();
let DATA = null, FILTER = "", MODE = "all";

function t(k) { return STATUS_I18N[LANG][k]; }
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function findTitle(f) { return LANG === "en" ? (f.title_en || f.title) : (f.title || f.title_en); }

document.getElementById("themebtn").addEventListener("click", () => {
  const cur = document.documentElement.dataset.theme === "light" ? "light" : "dark";
  const next = cur === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("theme", next); } catch (e) {}
});

function applyI18n() {
  document.documentElement.lang = LANG;
  document.querySelectorAll("[data-t]").forEach((el) => { el.textContent = t(el.dataset.t); });
  document.getElementById("filter").placeholder = t("filter_ph");
  document.querySelectorAll("#lang button").forEach((b) => b.classList.toggle("on", b.dataset.lang === LANG));
  if (DATA) render();
}

function tile(label, val, cls, extra) {
  return `<div class="stat ${cls || ""}" ${extra || ""}><b>${esc(label)}</b><span>${esc(val)}</span></div>`;
}
function rows(list, cols) {
  if (!list || !list.length) return `<p class="sub">${t("none")}</p>`;
  const head = `<tr>${cols.map((c) => `<th${c.num ? ' class="num"' : ""}>${esc(c.h)}</th>`).join("")}</tr>`;
  const body = list.map((r) =>
    `<tr>${cols.map((c) => `<td${c.num ? ' class="num"' : ""}>${c.html ? c.html(r) : esc(c.get(r))}</td>`).join("")}</tr>`).join("");
  return `<table class="table">${head}${body}</table>`;
}

function findingsCell(r) {
  if (!r.n) return `<span class="muted">${t("no_find")}</span>`;
  if (r.finds && r.finds.length) {
    return `<div class="findlist">` + r.finds.map((f) =>
      `<div class="findrow"><span class="badge ${esc(f.sev || "info")}">${esc(findTitle(f) || f.cve)}</span>` +
      `<span class="findcve"${f.inferred ? ` title="${esc(t("inferred"))}"` : ""}>` +
      `${f.inferred ? "≈ " : ""}${esc(f.cve)}</span></div>`).join("") + `</div>`;
  }
  // régi bejegyzés (v0.2.0 előtt): a konkrét CVE nincs naplózva, csak a súlyosságok
  return (r.sev || []).map((s) => `<span class="badge ${esc(s)}">${esc(s)}</span>`).join(" ");
}

function matchScan(r) {
  if (MODE === "hits" && !r.n) return false;
  if (MODE === "critical" && !((r.finds || []).some((f) => f.sev === "critical") || (r.sev || []).includes("critical"))) return false;
  if (FILTER) {
    const hay = ((r.target || "") + " " + (r.ip || "")).toLowerCase();
    if (!hay.includes(FILTER)) return false;
  }
  return true;
}

function render() {
  const d = DATA;
  const hitRate = d.total ? Math.round((d.with_findings / d.total) * 100) : 0;
  const crit = (d.sev && d.sev.critical) || 0;
  document.getElementById("tiles").innerHTML =
    tile(t("t_total"), d.total, "accent") +
    tile(t("t_today"), d.today) +
    tile(t("t_hits"), d.with_findings + " (" + hitRate + "%)", d.with_findings ? "bad" : "good") +
    tile(t("t_ext"), d.extended) +
    tile(t("t_unres"), d.unresolved) +
    tile(t("t_crit"), crit, "bad clickable" + (MODE === "critical" ? " active" : ""), 'id="crittile"');

  const ct = document.getElementById("crittile");
  if (ct) ct.addEventListener("click", () => { setMode(MODE === "critical" ? "all" : "critical"); });

  document.getElementById("targets").innerHTML = rows(d.top_targets,
    [{ h: t("c_target"), get: (r) => r.target }, { h: t("c_count"), num: true, get: (r) => r.n }]);
  document.getElementById("ips").innerHTML = rows(d.top_ips,
    [{ h: t("c_ip"), get: (r) => r.ip }, { h: t("c_count"), num: true, get: (r) => r.n }]);

  document.querySelectorAll("#pills button").forEach((b) => b.classList.toggle("on", b.dataset.f === MODE));
  const list = (d.recent || []).filter(matchScan);
  document.getElementById("scancount").textContent = t("scans_n")(list.length, d.total);
  document.getElementById("scans").innerHTML = rows(list,
    [{ h: t("c_time"), get: (r) => (r.ts || "").replace("T", " ").replace("+00:00", "") },
     { h: t("c_ip"), get: (r) => r.ip },
     { h: t("c_target"), get: (r) => r.target },
     { h: t("c_ext"), get: (r) => (r.extended ? "✓" : "") },
     { h: t("c_findings"), html: findingsCell }]);
}

function setMode(m) { MODE = m; render(); }

async function load() {
  const token = new URLSearchParams(location.search).get("token") || "";
  const note = document.getElementById("note");
  try {
    const res = await fetch("/api/stats" + (token ? "?token=" + encodeURIComponent(token) : ""),
      { headers: token ? { "X-Status-Token": token } : {} });
    if (res.status === 401) {
      note.textContent = t("no_auth"); note.classList.add("err"); note.hidden = false; return;
    }
    DATA = await res.json();
  } catch (e) {
    note.textContent = t("load_err"); note.classList.add("err"); note.hidden = false; return;
  }
  if (!DATA.enabled) { note.textContent = t("disabled"); note.hidden = false; }
  render();
}

document.getElementById("filter").addEventListener("input", (e) => { FILTER = e.target.value.trim().toLowerCase(); render(); });
document.querySelectorAll("#pills button").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.f)));
document.querySelectorAll("#lang button").forEach((b) => b.addEventListener("click", () => {
  LANG = b.dataset.lang; try { localStorage.setItem("lang", LANG); } catch (e) {} applyI18n();
}));

applyI18n();
load();
