# php2shell-scan — security audit

Scope: a public, version/fingerprint-based (non-exploitation) PHP php2shell CVE checker. It takes one
domain, resolves it, fetches the live host's HTTP response headers with a single `GET`, and reports
whether the advertised product version falls in a known-vulnerable range. It never sends a payload.

## Threat model

The tool is **public and unauthenticated** on the scan endpoint, so the main risks are:

1. **SSRF** — tricking the server into connecting to internal/cloud-metadata endpoints.
2. **Abuse as an attack relay / amplifier** — using the server to probe third parties at scale.
3. **Resource exhaustion** — slow-loris targets, huge responses, unbounded concurrency, ReDoS.
4. **Data exposure** — the usage log contains client IPs and target domains (personal-data adjacent).
5. **Response injection** — malicious target responses rendered in the browser (XSS).

## Controls in place

### SSRF (primary)
- Input is restricted to **domains only**; raw IP literals are rejected (`scanner.normalize_target`).
- The domain is resolved and filtered to **globally routable public IPs** via
  `ipaddress.is_global and not is_multicast` (`scanner._is_public`). Loopback, RFC1918, link-local
  (incl. 169.254/16 and cloud metadata 169.254.169.254), CGNAT (100.64/10), reserved and multicast
  addresses are all excluded. If nothing public remains → `no_public_ip`, no connection is made.
- The HTTP probe connects to the **already-validated IP**, not a re-resolution of the hostname, so a
  **DNS-rebinding** flip between the check and the connect cannot redirect us to a private address.
- Only ports **443/80** (and, in extended mode, 8443/8080) are contacted — no arbitrary-port SSRF.

### Non-exploitation / safe fetch
- **GET only**, `Connection: close`, **no redirect following** (raw socket), response capped at 128 KB,
  6 s socket timeout + a hard per-scan timeout of 40 s. Only the home page `/` is requested.
- Version detection is string comparison on `Server` / `X-Powered-By` (and a read-only Confluence
  version `<meta>` in extended mode). No request ever carries attack input.

### Abuse / DoS
- **Per-client-IP rate limit** (`PHP2SHELL_RATE_PER_MIN`, default 12/min), sliding 60 s window.
- **Global concurrency semaphore** (`PHP2SHELL_CONCURRENCY`, default 6) + uvicorn `--limit-concurrency`.
- One target per request; **no crawling, no subdomain enumeration**.
- Domain validated against a **linear** regex with a 253-char cap → no catastrophic backtracking (ReDoS).
- Request body target field capped at 255 chars.

### Web hardening
- Strict security headers on every response: `Content-Security-Policy` (default-src 'self',
  no inline/remote scripts), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy` (camera/mic/geo off).
- All target-derived strings are **HTML-escaped** before rendering (`app.js esc()`); the body is parsed
  server-side for a version only and is **never** sent to the browser.
- `/status` and `/api/stats` are gated by `PHP2SHELL_STATUS_TOKEN` (constant-time compare) and, in
  production, additionally placed **behind the Caddy passkey** — they are never public.
- Docs endpoints disabled (`docs_url=None`), server header suppressed, `robots.txt` disallow-all + noindex.

### Privacy (usage log)
- The background log (`auditlog.py`) stores only: timestamp, client IP, target domain, extended flag,
  finding count, severities. **No** response bodies, no browser fingerprint, no query strings.
- GDPR basis: legitimate interest (abuse prevention / operations). Optional pseudonymization
  (`PHP2SHELL_LOG_HASH_IP=1` → daily-salted SHA-256). Log lives outside the repo (`data/`, gitignored),
  file mode 700 dir in the container. Logging can be disabled entirely (`PHP2SHELL_LOG=off`).
- **Retention:** rotate/prune the log on the host (operational note in CLAUDE.local.md).

## Residual risks / accepted

- A version match is a **lead, not proof** of exploitability (backported fixes, WAF, hidden version).
  Surfaced prominently in the UI and README.
- The server can still be used to send a single, benign `GET /` to any public host the user names —
  equivalent to one curl. Rate/concurrency limits bound the volume; abuse is logged.
- IPv6 egress depends on the host; we try IPv4 first and fall back across resolved IPs.

## Pre-release checklist

- [ ] `python -m compileall -q app` clean; `python -c "import app.main"` OK.
- [ ] No server IP / infra / personal data committed (public repo). `data/` gitignored.
- [ ] In production: `/status` + `/api/stats` behind passkey; `PHP2SHELL_STATUS_TOKEN` set.
- [ ] `PHP2SHELL_LOG` points at a writable, host-rotated path; consider `PHP2SHELL_LOG_HASH_IP=1`.
- [ ] Caddy: `import headers` + `import access`, HSTS; app runs non-root, read-only FS, `cap_drop: [ALL]`.
