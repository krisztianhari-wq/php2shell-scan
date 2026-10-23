"""php2shell-scan – publikus, verzió/ujjlenyomat-alapú (NEM kihasználás) PHP php2shell CVE-szkenner.

Egy domaint kér, feloldja, a publikus host(ok) HTTP-fejlécét lekéri (GET), és jelzi a php2shell
párost (CVE-2026-109618 / CVE-2026-109619). Kapcsolóval a domain-recon teljes CVE-készlete.

Biztonság: GET-only, redirect nélkül, SSRF-szűrés (csak publikus IP), IP/perc rate-limit,
egyidejűség-korlát, domain-hosszkorlát, szigorú biztonsági fejlécek. Lásd AUDIT.md.
"""
from __future__ import annotations

import asyncio
import hmac
import os
import time
from collections import deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from . import __version__, auditlog, recheck, scanner, stats

STATIC = Path(__file__).resolve().parent / "static"

# --- korlátok (env-ből hangolható) ---
RATE_PER_MIN = int(os.environ.get("PHP2SHELL_RATE_PER_MIN", "12"))   # vizsgálat / IP / perc
MAX_CONCURRENCY = int(os.environ.get("PHP2SHELL_CONCURRENCY", "6"))  # globális párhuzamos vizsgálat
TRUST_PROXY = os.environ.get("PHP2SHELL_TRUST_PROXY", "1") == "1"    # Caddy mögött X-Forwarded-For
# A status oldal/statisztika mélységi védelme. Élesben a Caddy passkey-je kapuzza; ez plusz réteg.
STATUS_TOKEN = os.environ.get("PHP2SHELL_STATUS_TOKEN", "")

@asynccontextmanager
async def lifespan(app: "FastAPI"):
    task = asyncio.create_task(recheck.loop()) if recheck.ENABLED else None
    try:
        yield
    finally:
        if task:
            task.cancel()


app = FastAPI(title="php2shell-scan", version=__version__, docs_url=None, redoc_url=None, lifespan=lifespan)

_sem = asyncio.Semaphore(MAX_CONCURRENCY)
_hits: dict[str, deque] = {}
_hits_lock = asyncio.Lock()


def _client_ip(request: Request) -> str:
    if TRUST_PROXY:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "-"


async def _rate_ok(ip: str) -> bool:
    now = time.monotonic()
    async with _hits_lock:
        dq = _hits.setdefault(ip, deque())
        while dq and now - dq[0] > 60:
            dq.popleft()
        if len(dq) >= RATE_PER_MIN:
            return False
        dq.append(now)
        # alkalmi takarítás, hogy a dict ne nőjön korlátlanul
        if len(_hits) > 4096:
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > 120][:1024]:
                _hits.pop(k, None)
        return True


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'"),
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


@app.middleware("http")
async def _headers(request: Request, call_next):
    resp = await call_next(request)
    for k, v in _SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


@app.get("/healthz")
async def healthz():
    return {"ok": True, "version": __version__}


@app.get("/robots.txt")
async def robots():
    return PlainTextResponse("User-agent: *\nDisallow: /\n")


@app.get("/api/version")
async def version():
    return {"version": __version__, "name": "php2shell-scan"}


@app.post("/api/scan")
async def api_scan(request: Request):
    ip = _client_ip(request)
    if not await _rate_ok(ip):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001
        payload = {}
    target = str(payload.get("target", ""))[:255]
    extended = bool(payload.get("extended", False))

    try:
        host = scanner.normalize_target(target)
    except scanner.TargetError as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    try:
        async with _sem:
            result = await asyncio.wait_for(scanner.scan(host, extended=extended), timeout=40)
    except asyncio.TimeoutError:
        return JSONResponse({"error": "timeout"}, status_code=504)

    auditlog.record(ip, host, extended, result.get("findings", []),
                    resolved=result.get("resolved", False))
    return JSONResponse(result)


def _status_ok(request: Request) -> bool:
    """Ha van STATUS_TOKEN, egyeznie kell (fejléc vagy ?token=). Ha nincs, a Caddy-kapura hagyatkozunk."""
    if not STATUS_TOKEN:
        return True
    given = request.headers.get("x-status-token") or request.query_params.get("token") or ""
    return hmac.compare_digest(given, STATUS_TOKEN)


@app.get("/api/stats")
async def api_stats(request: Request):
    if not _status_ok(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = stats.summary()
    data["recheck"] = recheck.summary()
    return JSONResponse(data)


_NOCACHE = {"Cache-Control": "no-cache, no-store, must-revalidate"}
_INDEX = (STATIC / "index.html").read_text(encoding="utf-8").replace("__VER__", __version__)
_STATUS = (STATIC / "status.html").read_text(encoding="utf-8").replace("__VER__", __version__)


@app.get("/status")
async def status_page(request: Request):
    if not _status_ok(request):
        return PlainTextResponse("unauthorized", status_code=401)
    return Response(_STATUS, media_type="text/html; charset=utf-8", headers=_NOCACHE)


@app.get("/")
async def index():
    return Response(_INDEX, media_type="text/html; charset=utf-8", headers=_NOCACHE)


app.mount("/", StaticFiles(directory=str(STATIC)), name="static")
