"""A háttér-használati napló (auditlog) összegzése a status oldalhoz.

Csak olvas; a naplófájl utolsó részét dolgozza fel (korlátos memória). A kimenet üzemeltetői
áttekintés: összes/mai vizsgálat, találatos arány, extended arány, top célpontok és top vizsgáló IP-k.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
from collections import Counter
from pathlib import Path

_DEFAULT = Path(__file__).resolve().parent.parent / "data" / "usage.log.jsonl"
_MAX_LINES = 20000     # ennyi legutóbbi sort összegzünk


def _path() -> Path | None:
    val = os.environ.get("PHP2SHELL_LOG", "")
    if val.lower() == "off":
        return None
    return Path(val) if val else _DEFAULT


def _tail(path: Path, n: int) -> list[str]:
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            block = 65536
            data = b""
            while size > 0 and data.count(b"\n") <= n:
                step = min(block, size)
                size -= step
                fh.seek(size)
                data = fh.read(step) + data
        return data.decode("utf-8", "replace").splitlines()[-n:]
    except OSError:
        return []


def summary() -> dict:
    path = _path()
    out = {"enabled": path is not None, "total": 0, "today": 0, "with_findings": 0,
           "extended": 0, "unresolved": 0, "top_targets": [], "top_ips": [],
           "sev": {}, "recent": []}
    if path is None or not path.exists():
        return out

    today = _dt.date.today().isoformat()
    targets: Counter = Counter()
    ips: Counter = Counter()
    sevs: Counter = Counter()
    recent: list[dict] = []
    for line in _tail(path, _MAX_LINES):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        out["total"] += 1
        if str(e.get("ts", "")).startswith(today):
            out["today"] += 1
        n = int(e.get("n", 0) or 0)
        if n > 0:
            out["with_findings"] += 1
        if e.get("extended"):
            out["extended"] += 1
        if e.get("resolved") is False:
            out["unresolved"] += 1
        if e.get("target"):
            targets[e["target"]] += 1
        if e.get("ip"):
            ips[e["ip"]] += 1
        for s in (e.get("sev") or []):
            sevs[s] += 1
        recent.append(e)

    out["top_targets"] = [{"target": k, "n": v} for k, v in targets.most_common(15)]
    out["top_ips"] = [{"ip": k, "n": v} for k, v in ips.most_common(15)]
    out["sev"] = dict(sevs)
    out["recent"] = list(reversed(recent[-40:]))
    return out
