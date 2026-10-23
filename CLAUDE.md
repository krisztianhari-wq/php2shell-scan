# php2shell-scan – fejlesztői jegyzet

Publikus, **verzió/ujjlenyomat-alapú, NEM kihasználás** PHP php2shell CVE-szkenner. Egy domaint kér,
feloldja, a publikus host HTTP-fejlécét (GET) lekéri → PHP-verzió → php2shell páros
(CVE-2026-109618 / CVE-2026-109619). Kapcsolóval a domain-recon teljes CVE-készlete. Felhasználói
leírás (angol): README.md; biztonsági audit: AUDIT.md; üzemeltetés: CLAUDE.local.md (nincs gitben).

**Ez a repó PUBLIKUS.** Ide és a README/AUDIT-ba nem kerülhet szerver-IP, saját hosztnév/infra-részlet,
személyes név/e-mail, belső céges információ vagy konkrét (harmadik fél) célpont.

## Felépítés
- `app/cvescan.py` – detektálási logika (a domain-recon `cvescan.py`-ból csupaszítva). `php2shell_findings`
  (ALAP), `extended_version_cves` (PHP-CGI 4577 + Apache), `confluence_findings` (fingerprint). Kétnyelvű
  (`title`/`title_en`, `evidence`/`evidence_en`), `method: version|fingerprint`.
- `app/scanner.py` – `normalize_target` (domain-validáció, IP tiltva), `resolve_public_ips` (SSRF-mag:
  csak `is_global` IP), `scan()` nyers GET-only fejléc-lekérés az ELLENŐRZÖTT IP-re (Host/SNI = hostnév,
  nincs redirect, méret/időkorlát). Portok: 443/80, extended +8443/8080.
- `app/main.py` – FastAPI. `/api/scan` (POST), rate-limit (IP/perc), globális egyidejűség-sem, biztonsági
  fejlécek (CSP stb.). `/api/stats` + `/status` a használati statisztikának, opcionális `PHP2SHELL_STATUS_TOKEN`
  kapuval (élesben a Caddy passkey-je elé rakva – lásd deploy).
- `app/auditlog.py` – háttér használati napló (JSONL): ts, kliens-IP, célpont, extended, találatszám, sev.
  `PHP2SHELL_LOG` útvonal (`off`→nincs), `PHP2SHELL_LOG_HASH_IP=1`→napi sós SHA-256. Gitignore (`data/`).
- `app/stats.py` – a napló tail-összegzése a status oldalhoz (top célpont/IP, találatos arány, legutóbbiak).
  A v0.2.0 előtti, CVE nélküli találatokat olvasáskor kiegészíti (nem-extended kritikus → php2shell, ≈).
- `app/recheck.py` – **opt-in** (`PHP2SHELL_RECHECK=1`) 6 óránkénti újraellenőrzés: a valaha TALÁLATOS
  célpontokat újraszkenneli (extended), ahol a találat eltűnt → `fixed`, onnantól NEM szkenneli újra.
  Állapot: `data/recheck.json`; háttér-task a FastAPI `lifespan`-ben; a `/api/stats` `recheck` kulcsa adja
  az összesítőt (watched/fixed + listák). Alapból KI (a publikus kód nem szkennel automatikusan harmadik felet).
- `app/static/` – sadrobot UI, HU/EN (`i18n.js`), light/dark (`theme.js`). `index.html` fő oldal,
  `status.html`+`status.js` státusz. A `/` route behelyettesíti a `__VER__`-t (asset-URL verziózás).

## Indítás és teszt
- Venv: `/opt/homebrew/bin/python3.14 -m venv .venv && .venv/bin/pip install -r requirements.txt` (3.10+ kell).
- Launch config `php2shell-scan` → 127.0.0.1:8862.
- Teszt: nincs unit-teszt; CI-szerű ellenőrzés: `python -m compileall -q app`, import-smoke (`app.main`),
  és a cvescan logika gyors ellenőrzése (lásd AUDIT.md példák).
- Port: 8862 (konténerben is). Status: `/status`, statisztika `/api/stats`.

## Döntések
- **Csak domain**, nyers IP tiltva (`normalize_target`): így a feloldás + publikus-IP szűrés mindig lefut.
- SSRF: a feloldott, ellenőrzött IP-re csatlakozunk (nem old fel újra) → DNS-rebinding ellen.
- Alap = csak php2shell páros; a többi CVE csak `extended=true`-val (UI kapcsoló). A verzióegyezés nem
  bizonyít kihasználhatóságot – a UI/README kiemeli.
- Használati napló Krisz kérésére (ki mit vizsgált). GDPR: minimál mezők, opcionális IP-pszeudonimizálás,
  a napló a repón kívül (gitignore). A status oldal üzemeltetői nézet, élesben passkey mögött.

## Kiadás / deploy
- /release skill (verzióemelés + tag). Verzió: `app/__init__.py __version__` (most 0.1.0) + `/api/version` + lábléc.
- /deploy-sadrobot: publikus konténer-app (SADROBOT-INFRA.md §7c), host `php2shell.sadrobot.eu`. A **`/status`
  és `/api/stats` útvonal passkey (oauth2) mögé** kerül a Caddyban; a fő oldal publikus. `PHP2SHELL_LOG=/data/...`.
