"""Ismert kritikus CVE-k felismerése HTTP-fejlécből / könnyű ujjlenyomatból – NEM kihasználás.

Két csoport, külön jelölve:

  method="version":     a `Server` / `X-Powered-By` fejlécből kiolvasott termék+verzió összevetése
                        ismert sebezhető tartományokkal (PHP, Apache httpd).
  method="fingerprint": kíméletes, GET-only ujjlenyomat (pl. Confluence verzió a HTML-ből) →
                        ismert kritikus CVE.

Az ALAP ellenőrzés a PHP php2shell páros (CVE-2026-109618 / CVE-2026-109619), kizárólag a
fejlécből kiolvasott PHP-verzió alapján. A többi CVE csak akkor fut, ha a hívó `extended=True`-t kér.

A verzióegyezés NEM bizonyítja a kihasználhatóságot (lehet backportált javítás, WAF, stb.).
A találatok kétnyelvűek: title/evidence (HU) + title_en/evidence_en (EN); minden ellenőrzés hibatűrő.

A logika a sadrobot domain-recon `cvescan.py`-ból származik, erre az eszközre csupaszítva/adaptálva.
"""
from __future__ import annotations

import re


def _ver_tuple(s: str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _f(id_, cve, sev, title_hu, title_en, ev_hu, ev_en, method):
    return {"id": id_, "cve": cve, "severity": sev, "method": method,
            "title": title_hu, "title_en": title_en, "evidence": ev_hu, "evidence_en": ev_en}


# ---------------- PHP ----------------
# php2shell (ALAP): a 8.2–8.5 ágakon a megadott kiadások javítottak; a régebbi ágak EOL → érintettnek vesszük.
_PHP2SHELL_FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
_PHP2_FIX = "8.5.12 / 8.4.27 / 8.3.36 / 8.2.35"
# PHP-CGI argumentuminjekció (EXTENDED): csak Windows + CGI/CGI-FastCGI alatt kritikus.
_PHP_4577_FIXED = {(8, 1): (8, 1, 29), (8, 2): (8, 2, 20), (8, 3): (8, 3, 8)}


def _php_version(server: str, powered_by: str):
    m = re.search(r"PHP/[\d.]+", (powered_by or "") + " " + (server or ""))
    return _ver_tuple(m.group(0)) if m else None


def php2shell_findings(server: str = "", powered_by: str = "") -> list[dict]:
    """ALAP: a PHP php2shell páros (CVE-2026-109618 / CVE-2026-109619) verzió-alapon."""
    ver = _php_version(server, powered_by)
    if not ver:
        return []
    vs = ".".join(map(str, ver))
    branch = ver[:2]
    fixed = _PHP2SHELL_FIXED.get(branch)
    # Ismert ág: javítás alatti verzió érintett. Ismeretlen (régebbi) ág < 8.2 → EOL, érintett.
    if (fixed and ver < fixed) or (not fixed and ver < (8, 2)):
        return [_f("php2shell", "CVE-2026-109618 / CVE-2026-109619", "critical",
                   "PHP php2shell RCE", "PHP php2shell RCE",
                   f"PHP {vs} — javítva: {_PHP2_FIX} (alapértelmezett konfiguráció érintett)",
                   f"PHP {vs} — fixed: {_PHP2_FIX} (default configuration affected)", "version")]
    return []


def _php_cgi_findings(server: str, powered_by: str) -> list[dict]:
    ver = _php_version(server, powered_by)
    if not ver:
        return []
    branch = ver[:2]
    f4577 = _PHP_4577_FIXED.get(branch)
    if not f4577 or ver >= f4577:
        return []
    vs = ".".join(map(str, ver))
    win = bool(re.search(r"win(dows|32|64)|microsoft-iis", server or "", re.I))
    sev = "critical" if win else "high"
    note_hu = "Windows+CGI megerősítve" if win else "csak Windows+CGI – ellenőrizendő"
    note_en = "Windows+CGI confirmed" if win else "Windows+CGI only – verify"
    return [_f("php-cgi-arginject", "CVE-2024-4577", sev,
               "PHP-CGI argumentuminjekció (RCE)", "PHP-CGI argument injection (RCE)",
               f"PHP {vs} — javítva: 8.1.29 / 8.2.20 / 8.3.8 ({note_hu})",
               f"PHP {vs} — fixed: 8.1.29 / 8.2.20 / 8.3.8 ({note_en})", "version")]


# ---------------- Apache httpd (EXTENDED) ----------------
def _apache_findings(server: str) -> list[dict]:
    m = re.search(r"Apache/(\d+)\.(\d+)\.(\d+)", server or "")
    if not m:
        return []
    ver = tuple(int(x) for x in m.groups())
    vs = ".".join(map(str, ver))
    out = []
    if ver in ((2, 4, 49), (2, 4, 50)):
        cve = "CVE-2021-42013" + (" / CVE-2021-41773" if ver == (2, 4, 49) else "")
        out.append(_f("apache-path-traversal", cve, "critical",
                      "Apache path traversal → RCE", "Apache path traversal → RCE",
                      f"Apache {vs} — javítva: 2.4.51", f"Apache {vs} — fixed: 2.4.51", "version"))
    if (2, 4, 0) <= ver <= (2, 4, 48):
        out.append(_f("apache-mod-proxy-ssrf", "CVE-2021-40438", "critical",
                      "Apache mod_proxy SSRF", "Apache mod_proxy SSRF",
                      f"Apache {vs} — javítva: 2.4.49 (mod_proxy esetén)",
                      f"Apache {vs} — fixed: 2.4.49 (mod_proxy only)", "version"))
    return out


def extended_version_cves(server: str = "", powered_by: str = "") -> list[dict]:
    """EXTENDED verzió-alapú találatok a php2shell páron FELÜL (PHP-CGI, Apache httpd)."""
    out = []
    out += _php_cgi_findings(server, powered_by)
    out += _apache_findings(server)
    return out


# ---------------- EXTENDED ujjlenyomat-alapú (kíméletes GET) ----------------
_CONF_VER = re.compile(r'ajs-version-number"\s+content="(\d+)\.(\d+)\.(\d+)', re.I)
_CONF_26134_FIXED = {(7, 4): (7, 4, 17), (7, 13): (7, 13, 7), (7, 14): (7, 14, 3), (7, 15): (7, 15, 2),
                     (7, 16): (7, 16, 4), (7, 17): (7, 17, 4), (7, 18): (7, 18, 1)}
_CONF_22515_FIXED = {(8, 0): (8, 5, 2), (8, 1): (8, 5, 2), (8, 2): (8, 5, 2),
                     (8, 3): (8, 3, 3), (8, 4): (8, 4, 3), (8, 5): (8, 5, 2)}


def confluence_findings(body: str) -> list[dict]:
    """EXTENDED ujjlenyomat: Confluence verzió a HTML-ből → CVE-2022-26134 / CVE-2023-22515."""
    body = body or ""
    if "ajs-version-number" not in body and "Confluence" not in body:
        return []
    out: list[dict] = []
    m = _CONF_VER.search(body)
    if not m:
        return [_f("confluence", "—", "info", "Atlassian Confluence észlelve", "Atlassian Confluence detected",
                   "verzió nem olvasható ki – ellenőrizd a CVE-2022-26134 / CVE-2023-22515 ellen",
                   "version not readable – check against CVE-2022-26134 / CVE-2023-22515", "fingerprint")]
    ver = tuple(int(x) for x in m.groups()); vs = ".".join(map(str, ver)); branch = ver[:2]
    f1 = _CONF_26134_FIXED.get(branch)
    if f1 and ver < f1:
        fx = ".".join(map(str, f1))
        out.append(_f("confluence-ognl", "CVE-2022-26134", "critical",
                      "Confluence OGNL-injekció (RCE)", "Confluence OGNL injection (RCE)",
                      f"Confluence {vs} — javítva: {fx}", f"Confluence {vs} — fixed: {fx}", "fingerprint"))
    f2 = _CONF_22515_FIXED.get(branch)
    if f2 and ver < f2:
        fx = ".".join(map(str, f2))
        out.append(_f("confluence-authbypass", "CVE-2023-22515", "critical",
                      "Confluence jogosultság-megkerülés", "Confluence broken access control",
                      f"Confluence {vs} — javítva: {fx}", f"Confluence {vs} — fixed: {fx}", "fingerprint"))
    return out
