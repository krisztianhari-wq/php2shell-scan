# Changelog

## 0.2.0 — 2026-10-23
- Status page: full scan log — every scan is listed (not just the last 40), with a text filter
  (domain / IP) and All / With-findings / Critical pills.
- Status page: the **Critical flags** tile is now clickable — it filters the log to critical hits.
- Findings are shown per scan (CVE badges); the usage log now records the matched CVEs
  (identifier + severity + bilingual title), so the critical hits are inspectable.
- Status page is now bilingual (HU/EN), matching the scanner page.

## 0.1.0 — 2026-10-22
- Initial release. Public, version/fingerprint-based (non-exploitation) PHP php2shell CVE scanner
  (CVE-2026-109618 / CVE-2026-109619), with optional extended CVE set.
- SSRF-guarded GET-only probing, per-IP rate limit, strict CSP.
- Background usage log + passkey-protected /status statistics page.
- Live at php2shell.sadrobot.eu.
