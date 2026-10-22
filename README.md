# php2shell-scan

A tiny, **public, version-based** check for the PHP **php2shell** RCE pair
(**CVE-2026-109618 / CVE-2026-109619**). Enter a domain; the tool resolves it, fetches the live
host's HTTP headers with a single `GET`, reads the PHP version from `Server` / `X-Powered-By`, and
flags whether that version is in the affected range.

**This is not an exploit.** It never sends a payload and never follows redirects — it only reads the
home-page response headers (and, in extended mode, the body for a lightweight product fingerprint).
A version match does **not** prove exploitability: the server may hide its version, run a backported
fix, or sit behind a WAF. Treat every result as a lead to verify, not a confirmation.

> **Authorized targets only.** Only scan systems you are authorized to test in writing.

## What it checks

- **Default — PHP php2shell:** CVE-2026-109618 / CVE-2026-109619. Affected when the PHP version is
  below the fixed releases **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**; older branches are EOL and treated
  as affected.
- **Extended (optional toggle):** PHP-CGI argument injection **CVE-2024-4577** (critical on
  Windows + CGI), Apache httpd **CVE-2021-41773 / CVE-2021-42013** (2.4.49 / 2.4.50) and
  **CVE-2021-40438** (≤ 2.4.48), plus an Atlassian Confluence version fingerprint for
  **CVE-2022-26134 / CVE-2023-22515**.

Findings are bilingual (HU/EN) and tagged by method: `version` (from headers) or `fingerprint`
(lightweight GET of the home page).

## Safety

- **GET only, no redirects, size- and time-limited** requests.
- **SSRF protection:** the target is resolved and only **public, globally routable** IPs are
  contacted; loopback / private / link-local / CGNAT / reserved addresses are refused. The scanner
  connects to the already-validated IP (not a second resolution), mitigating DNS rebinding.
- **Domain validation** with a length cap (ReDoS-safe), **per-IP rate limiting** and a global
  concurrency cap.
- A single target per request — no crawling, no subdomain enumeration.

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8862
```

Open <http://127.0.0.1:8862>.

### Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `PHP2SHELL_RATE_PER_MIN` | `12` | Scans allowed per client IP per minute |
| `PHP2SHELL_CONCURRENCY` | `6` | Global concurrent scans |
| `PHP2SHELL_TRUST_PROXY` | `1` | Trust `X-Forwarded-For` (behind a reverse proxy) |
| `PHP2SHELL_LOG` | `data/usage.log.jsonl` | Usage log path; `off` disables it |
| `PHP2SHELL_LOG_HASH_IP` | – | `1` pseudonymizes client IPs (daily-salted SHA-256) |
| `PHP2SHELL_STATUS_TOKEN` | – | If set, `/status` and `/api/stats` require this token |

## License

MIT © sadrobot. See [LICENSE](LICENSE).
