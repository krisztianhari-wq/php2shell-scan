# Changelog

## 0.5.0 — 2026-10-23
- Re-check: configurable interval in minutes (`PHP2SHELL_RECHECK_MINUTES`, default 60; the old
  `PHP2SHELL_RECHECK_HOURS` still works) — re-checks more often than the previous fixed 6h.
- Re-check: new "unreachable" state — a watched target that no longer resolves or no longer responds
  (not the same as "fixed", which responds but has no finding). Tracked with a first-unreachable
  timestamp and a miss counter, and kept under watch in case it comes back.
- Status page: an "Unreachable" tile and a dedicated section (target, unreachable-since, miss count,
  last known findings), next to Fixed/gone and Watched.

## 0.4.1 — 2026-10-23
- Fix: status page tables overflowed horizontally on mobile (long CVE ids, monospace) — tables are now
  in a scrollable wrapper, and CVE ids wrap on narrow screens. No more horizontal page scroll.

## 0.4.0 — 2026-10-23
- Scheduled re-check (opt-in, PHP2SHELL_RECHECK=1): every 6h (PHP2SHELL_RECHECK_HOURS) it re-scans the
  targets that have had a finding, and tracks where the finding disappeared (fixed). A fixed target is
  dropped from the loop — it is not scanned again. Status page shows a "Fixed (gone)" tile plus a
  re-check section (fixed/gone targets with date + the CVEs that disappeared, and still-vulnerable
  watched targets). Default off — the public code does not auto-scan third parties.

## 0.3.0 — 2026-10-23
- Scanner page: added a "limits" notice — this is a version-based indicator, not a full assessment
  ("no finding" ≠ safe; no exploitation, to avoid stressing the target) — and a collapsible
  "precise, local verification" guide (php -v / php-fpm -v, distro backport changelogs, compare to
  fixed releases, on-host authenticated check). Bilingual (HU/EN).

## 0.2.4 — 2026-10-23
- Status page: shows re-scanned findings. Pre-0.2.0 extended hits (where the exact CVE wasn't logged)
  were re-scanned; the matched CVEs are now in the log, marked ⟳ (with date tooltip). Entries that are
  no longer vulnerable show "re-scanned: no finding anymore".

## 0.2.3 — 2026-10-23
- Status page: back-fill the CVE for pre-0.2.0 log entries that predate per-finding CVE logging.
  In default (non-extended) mode only the php2shell pair can match, so a non-extended critical hit
  is shown as CVE-2026-109618/109619, marked inferred (≈, with a tooltip). The log file is not
  rewritten — the inference happens at read time.

## 0.2.2 — 2026-10-23
- Status page: each finding now shows the exact CVE id next to the title (not only on hover),
  so you can see which CVE the scan matched.

## 0.2.1 — 2026-10-23
- Fix: the status page loaded its JS/CSS without a version query, so browsers kept serving the old
  `status.js` (language switch and new log view appeared but did nothing). Assets are now versioned
  (`?v=<version>`) and the `/status` and `/` HTML is served with `no-cache`.

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
