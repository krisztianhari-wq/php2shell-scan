"""Egyetlen célpont biztonságos, GET-only vizsgálata.

Folyamat:
  1. domain-validáció (hosszkorlát, karakterkészlet) – ReDoS és badinput ellen,
  2. DNS-feloldás (A/AAAA), SSRF-szűrés: csak PUBLIKUS, routolható IP marad,
  3. a feloldott, ellenőrzött IP-re csatlakozva (nem old fel újra → DNS-rebinding ellen) GET / a 443/80-on,
     a Host/SNI a hostnév; nincs átirányítás-követés, rövid timeout, méretkorlát,
  4. Server / X-Powered-By → php2shell (alap) + opcionálisan a többi CVE.

Semmilyen írás, semmilyen kihasználás – kizárólag a főoldal fejléce és (extended esetén) törzse.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl

from . import cvescan

# Web-portok: alap a 443 és 80. Extended módban pár tipikus alternatív web-port is.
_BASE_PORTS = [(443, True), (80, False)]
_EXTRA_PORTS = [(8443, True), (8080, False)]
_HTTP_MAX = 131072          # a válaszból legfeljebb ennyi bájtot olvasunk
_TIMEOUT = 6.0
_UA = "php2shell-scan/1.0 (+https://github.com/sadrobot; authorized use only)"

# Domain: max 253 karakter, pontokkal tagolt címkék; a regex lineáris (nincs katasztrofális visszalépés).
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")


class TargetError(ValueError):
    """Érvénytelen vagy nem engedélyezett célpont (üzenet kétnyelvű kulcsként)."""


def normalize_target(raw: str) -> str:
    """Levágja a sémát/utat/portot, kisbetűsít, validál. IP-t NEM fogadunk el (csak domaint)."""
    if not raw or len(raw) > 255:
        raise TargetError("bad_domain")
    s = raw.strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)        # séma le
    s = s.split("/", 1)[0]                  # út le
    s = s.split("?", 1)[0].split("#", 1)[0]
    s = s.split(":", 1)[0]                  # port le
    s = s.rstrip(".")
    if s.startswith("[") or re.match(r"^\d+\.\d+\.\d+\.\d+$", s):
        raise TargetError("no_ip")          # nyers IP-t nem engedünk (csak feloldott, publikus domain)
    if len(s) > 253 or not _DOMAIN_RE.match(s):
        raise TargetError("bad_domain")
    return s


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Csak globálisan routolható cím: loopback/privát/link-local/CGNAT/reserved/multicast NEM.
    return a.is_global and not a.is_multicast


async def resolve_public_ips(host: str) -> list[str]:
    """A/AAAA feloldás, majd csak a publikus IP-k. SSRF-védelem magja."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=5.0)
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        return []
    ips: list[str] = []
    for fam, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in ips and _is_public(ip):
            ips.append(ip)
    return ips


def _http_get_sync(host: str, ip: str, port: int, tls: bool) -> bytes | None:
    """Nyers GET / az ELLENŐRZÖTT IP-re (Host/SNI = hostnév). Nincs redirect-követés."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(_TIMEOUT)
    sock = raw
    try:
        raw.connect((ip, port))
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE          # célpont lehet self-signed; mi csak fejlécet olvasunk
            sock = ctx.wrap_socket(raw, server_hostname=host)
        req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {_UA}\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n").encode()
        sock.sendall(req)
        buf = b""
        while len(buf) < _HTTP_MAX:
            chunk = sock.recv(16384)
            if not chunk:
                break
            buf += chunk
        return buf
    except (OSError, ssl.SSLError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _parse(buf: bytes) -> dict:
    head, _, body = buf.partition(b"\r\n\r\n")
    head_txt = head.decode("latin-1", "replace")
    status = None
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})", head_txt)
    if m:
        status = int(m.group(1))
    headers: dict[str, str] = {}
    for line in head_txt.split("\r\n")[1:]:
        k, _, v = line.partition(":")
        if v:
            headers[k.strip().lower()] = v.strip()
    return {
        "status": status,
        "server": headers.get("server", "")[:160],
        "powered_by": headers.get("x-powered-by", "")[:160],
        "body": body[:_HTTP_MAX].decode("utf-8", "replace"),
    }


async def _probe_port(host: str, ip: str, port: int, tls: bool) -> dict | None:
    try:
        buf = await asyncio.wait_for(
            asyncio.to_thread(_http_get_sync, host, ip, port, tls), timeout=_TIMEOUT + 2)
    except (asyncio.TimeoutError, OSError):
        return None
    if not buf:
        return None
    out = _parse(buf)
    out.update(scheme="https" if tls else "http", port=port)
    return out


async def scan(host: str, extended: bool = False) -> dict:
    """Egy célpont teljes, biztonságos vizsgálata. -> dict a UI/JSON számára."""
    host = normalize_target(host)
    ips = await resolve_public_ips(host)
    if not ips:
        return {"host": host, "resolved": False, "ips": [], "ports": [], "findings": [],
                "reason": "no_public_ip"}

    # IPv4-et előre soroljuk (szélesebb kimenő-kompatibilitás), de IPv6-ra is próbálunk.
    ordered = sorted(ips, key=lambda x: (":" in x, ips.index(x)))
    ports = _BASE_PORTS + (_EXTRA_PORTS if extended else [])
    probes: list[dict] = []
    used_ip = None
    # Próbáljuk az IP-ket sorban; az első, amelyik legalább egy porton válaszol, nyer
    # (így a nem elérhető IPv6 nem fojtja el a működő IPv4-et).
    for ip in ordered[:3]:
        for port, tls in ports:
            p = await _probe_port(host, ip, port, tls)
            if p:
                probes.append(p)
        if probes:
            used_ip = ip
            break

    # Fejléc összegzése: az első olyan válasz, ahol van Server/X-Powered-By.
    server = powered = body = ""
    for p in probes:
        server = server or p.get("server", "")
        powered = powered or p.get("powered_by", "")
        if (p.get("body") and not body) or (not body and extended):
            body = body or p.get("body", "")

    findings = cvescan.php2shell_findings(server, powered)
    if extended:
        findings += cvescan.extended_version_cves(server, powered)
        findings += cvescan.confluence_findings(body)

    # a body-t nem adjuk vissza (méret + adattakarékosság)
    for p in probes:
        p.pop("body", None)
    return {
        "host": host,
        "resolved": True,
        "ips": ips,
        "used_ip": used_ip,
        "server": server or None,
        "powered_by": powered or None,
        "ports": probes,
        "findings": findings,
        "extended": extended,
    }
