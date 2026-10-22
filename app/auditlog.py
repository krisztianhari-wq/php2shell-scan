"""Háttér-használati napló: ki (kliens-IP) mely domaint vizsgálta, mikor, milyen eredménnyel.

Cél: üzemeltetői/biztonsági áttekintés és visszaélés-felderítés (GDPR jogalap: jogos érdek).
Adattakarékos: NINCS teljes válasz, NINCS böngésző-ujjlenyomat; csak a visszaélés-követéshez
szükséges mezők. Soronként egy JSON (JSONL), a repóba NEM kerül (gitignore), külön állítható útvonal.

Env:
  PHP2SHELL_LOG         a napló útvonala (alap: <projekt>/data/usage.log.jsonl); "off" → nincs naplózás
  PHP2SHELL_LOG_HASH_IP ha "1", a kliens-IP-t nem nyersen, hanem napi sóval SHA-256-olva tároljuk
                        (pszeudonimizálás – a visszaélő így is összefűzhető, de a nyers IP nem marad meg)
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import threading
from pathlib import Path

_LOCK = threading.Lock()
_DEFAULT = Path(__file__).resolve().parent.parent / "data" / "usage.log.jsonl"


def _path() -> Path | None:
    val = os.environ.get("PHP2SHELL_LOG", "")
    if val.lower() == "off":
        return None
    return Path(val) if val else _DEFAULT


def _client_ip(raw_ip: str) -> str:
    if os.environ.get("PHP2SHELL_LOG_HASH_IP") == "1":
        day = _dt.date.today().isoformat()
        return "h:" + hashlib.sha256(f"{day}|{raw_ip}".encode()).hexdigest()[:20]
    return raw_ip


def record(client_ip: str, target: str, extended: bool, findings: list[dict],
           resolved: bool = True) -> None:
    """Egy vizsgálat naplózása. Hibatűrő: naplózási hiba sosem töri meg a kérést."""
    path = _path()
    if path is None:
        return
    sevs = sorted({f.get("severity", "info") for f in findings})
    entry = {
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "ip": _client_ip(client_ip or "-"),
        "target": (target or "")[:255],
        "extended": bool(extended),
        "resolved": bool(resolved),
        "n": len(findings),
        "sev": sevs,
    }
    try:
        with _LOCK:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass
