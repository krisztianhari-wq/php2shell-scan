// Státusz oldal: /api/stats → csempék + táblák + teljes vizsgálati napló (szűrhető).
// A "Kritikus jelzés" csempe a kritikus találatos vizsgálatokra szűr. HU/EN. ?token= továbbmegy az API-nak.
const STATUS_I18N = {
  hu: {
    status: "Státusz", back_scanner: "← szkenner",
    eyebrow: "Használati statisztika",
    lead: "A háttér-használati naplóból – ki (vizsgáló IP) mely célpontot vizsgálta. Üzemeltetői nézet, nem publikus.",
    t_total: "Összes vizsgálat", t_today: "Ma", t_hits: "Találatos", t_ext: "Bővített",
    t_unres: "Feloldatlan", t_crit: "Kritikus jelzés", t_fixed: "Javítva (eltűnt)",
    recheck_title: "Időzített újraellenőrzés", recheck_off: "Az időzített újraellenőrzés ki van kapcsolva.",
    rc_every: (h) => `${h} óránként`, rc_last: "utolsó futás:", rc_never: "még nem futott",
    rc_fixed_h: "Javítva / eltűnt", rc_watched_h: "Figyelt – még sebezhető",
    rc_gone_when: "Eltűnt", rc_lastcheck: "Utolsó ellenőrzés", rc_none_fixed: "még nincs javított találat",
    rc_none_watched: "nincs figyelt (sebezhető) célpont",
    top_targets: "Top célpontok", top_ips: "Top vizsgáló IP-k", all_scans: "Összes vizsgálat",
    c_target: "Célpont", c_ip: "Vizsgáló IP", c_count: "db", c_time: "Időpont (UTC)",
    c_ext: "Ext", c_findings: "Találatok",
    f_all: "Mind", f_hits: "Találatos", f_critical: "Kritikus",
    filter_ph: "Szűrés domainre vagy IP-re…",
    inferred: "Következtetett: alap (nem bővített) módban csak a php2shell páros futhat, így a kritikus találat biztosan ez. A régi bejegyzésnél a konkrét CVE még nem volt naplózva.",
    rescanned: "Újraszkennelve (a vizsgálat idején a konkrét CVE még nem volt naplózva) –",
    rescan_clean: "újraszkennelve: már nincs találat",
    rescan_err: "újraszkennelés sikertelen",
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
    t_unres: "Unresolved", t_crit: "Critical flags", t_fixed: "Fixed (gone)",
    recheck_title: "Scheduled re-check", recheck_off: "Scheduled re-check is off.",
    rc_every: (h) => `every ${h}h`, rc_last: "last run:", rc_never: "not run yet",
    rc_fixed_h: "Fixed / gone", rc_watched_h: "Watched – still vulnerable",
    rc_gone_when: "Gone since", rc_lastcheck: "Last check", rc_none_fixed: "no fixed findings yet",
    rc_none_watched: "no watched (vulnerable) targets",
    top_targets: "Top targets", top_ips: "Top scanner IPs", all_scans: "All scans",
    c_target: "Target", c_ip: "Scanner IP", c_count: "n", c_time: "Time (UTC)",
    c_ext: "Ext", c_findings: "Findings",
    f_all: "All", f_hits: "With findings", f_critical: "Critical",
    filter_ph: "Filter by domain or IP…",
    inferred: "Inferred: in default (non-extended) mode only the php2shell pair can run, so a critical hit is certainly this one. The old entry did not record the exact CVE yet.",
    rescanned: "Re-scanned (the exact CVE wasn't logged at scan time) –",
    rescan_clean: "re-scanned: no finding anymore",
    rescan_err: "re-scan failed",
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

function sevBadges(r) {
  return (r.sev || []).map((s) => `<span class="badge ${esc(s)}">${esc(s)}</span>`).join(" ");
}

function findingsCell(r) {
  if (!r.n) return `<span class="muted">${t("no_find")}</span>`;
  if (r.finds && r.finds.length) {
    return `<div class="findlist">` + r.finds.map((f) => {
      let mark = "";
      if (f.inferred) mark = `<span class="fmark" title="${esc(t("inferred"))}">≈ </span>`;
      else if (f.rescanned) mark = `<span class="fmark" title="${esc(t("rescanned"))} ${esc(f.rescanned)}">⟳ </span>`;
      return `<div class="findrow"><span class="badge ${esc(f.sev || "info")}">${esc(findTitle(f) || f.cve)}</span>` +
        `<span class="findcve">${mark}${esc(f.cve)}</span></div>`;
    }).join("") + `</div>`;
  }
  // újraszkennelve, de már nincs találat (időközben javították)
  if (r.rescan_clean) return `<span class="muted" title="${esc(r.rescanned || "")}">⟳ ${esc(t("rescan_clean"))}</span> ${sevBadges(r)}`;
  if (r.rescan_err) return `<span class="muted">⟳ ${esc(t("rescan_err"))}</span> ${sevBadges(r)}`;
  // régi bejegyzés (v0.2.0 előtt), nem következtethető: csak a súlyosságok
  return sevBadges(r);
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
    tile(t("t_crit"), crit, "bad clickable" + (MODE === "critical" ? " active" : ""), 'id="crittile"') +
    (d.recheck && d.recheck.enabled ? tile(t("t_fixed"), d.recheck.fixed, "good") : "");

  const ct = document.getElementById("crittile");
  if (ct) ct.addEventListener("click", () => { setMode(MODE === "critical" ? "all" : "critical"); });

  renderRecheck(d.recheck);

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

function cveBadges(finds) {
  if (!finds || !finds.length) return "";
  return `<div class="findlist">` + finds.map((f) =>
    `<div class="findrow"><span class="badge ${esc(f.sev || "info")}">${esc(findTitle(f) || f.cve)}</span>` +
    `<span class="findcve">${esc(f.cve)}</span></div>`).join("") + `</div>`;
}

function renderRecheck(rc) {
  const card = document.getElementById("recheckcard");
  if (!card) return;
  card.hidden = false;
  const title = document.getElementById("rctitle");
  const meta = document.getElementById("rcmeta");
  const body = document.getElementById("recheck");
  title.textContent = t("recheck_title");
  if (!rc || !rc.enabled) {
    meta.textContent = "";
    body.innerHTML = `<p class="sub">${t("recheck_off")}</p>`;
    return;
  }
  const last = rc.last_run ? (rc.last_run.replace("T", " ").replace("+00:00", "") + " UTC") : t("rc_never");
  meta.textContent = t("rc_every")(rc.hours) + " · " + t("rc_last") + " " + last;

  const fixed = rows(rc.fixed_list,
    [{ h: t("c_target"), get: (r) => r.target },
     { h: t("rc_gone_when"), get: (r) => (r.fixed_at || "").replace("T", " ").replace("+00:00", "") },
     { h: t("c_findings"), html: (r) => cveBadges(r.findings) || `<span class="muted">${t("no_find")}</span>` }]);
  const watched = rows(rc.watched_list,
    [{ h: t("c_target"), get: (r) => r.target },
     { h: t("c_findings"), html: (r) => cveBadges(r.findings) },
     { h: t("rc_lastcheck"), get: (r) => (r.last_check || "").replace("T", " ").replace("+00:00", "") }]);

  body.innerHTML =
    `<h3 class="subh good">✓ ${esc(t("rc_fixed_h"))} (${rc.fixed})</h3>` +
    (rc.fixed_list && rc.fixed_list.length ? fixed : `<p class="sub">${t("rc_none_fixed")}</p>`) +
    `<h3 class="subh bad">⚠ ${esc(t("rc_watched_h"))} (${rc.watched})</h3>` +
    (rc.watched_list && rc.watched_list.length ? watched : `<p class="sub">${t("rc_none_watched")}</p>`);
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
