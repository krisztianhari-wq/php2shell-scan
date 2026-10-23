"""Időzített újraellenőrzés: a valaha TALÁLATOS célpontokat 6 óránként újraszkenneli, és követi,
hol tűnt el a találat (javították). Ha egy célpont javult, onnantól NEM szkenneljük tovább.

Felelős működés:
  - csak a már találatos célpontokat nézi (a usage-naplóból), nem minden beírt domaint;
  - a javult célpontot kiveszi a körből ("fixed", és nem próbálja újra);
  - alapból KIKAPCSOLVA (opt-in): csak akkor fut, ha PHP2SHELL_RECHECK=1. A publikus kód így nem
    szkennel automatikusan harmadik feleket; az üzemeltető kapcsolja be a saját felelősségére.

Állapot: egy JSON a napló mellett (data/recheck.json). GET-only, SSRF-guardos szkennelés (scanner.py).
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import json
import os
from pathlib import Path

from . import scanner

HOURS = max(1, int(os.environ.get("PHP2SHELL_RECHECK_HOURS", "6") or "6"))
ENABLED = os.environ.get("PHP2SHELL_RECHECK", "").lower() in ("1", "on", "true", "yes")
_CONCURRENCY = 4


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _log_path() -> Path:
    val = os.environ.get("PHP2SHELL_LOG", "")
    if val and val.lower() != "off":
        return Path(val)
    return Path(__file__).resolve().parent.parent / "data" / "usage.log.jsonl"


def _state_path() -> Path:
    return _log_path().parent / "recheck.json"


def load_state() -> dict:
    try:
        return json.loads(_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"targets": {}, "last_run": None, "generated": None}


def save_state(st: dict) -> None:
    try:
        p = _state_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(st, ensure_ascii=False, indent=1), encoding="utf-8")
    except OSError:
        pass


def _hit_targets() -> set[str]:
    """A usage-naplóból a valaha találatos (n>0) egyedi célpontok."""
    out: set[str] = set()
    p = _log_path()
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("n", 0) and e.get("target"):
                out.add(e["target"])
    except OSError:
        pass
    return out


def seconds_until_due(st: dict | None = None) -> float:
    """Hány másodperc a következő esedékes futásig (0 = most esedékes)."""
    st = st if st is not None else load_state()
    last = st.get("last_run")
    if not last:
        return 0.0
    try:
        t = _dt.datetime.fromisoformat(last)
    except ValueError:
        return 0.0
    due = t + _dt.timedelta(hours=HOURS)
    return max(0.0, (due - _dt.datetime.now(_dt.timezone.utc)).total_seconds())


def _finds(findings: list[dict]) -> list[dict]:
    return [{"cve": f.get("cve", ""), "sev": f.get("severity", "info"),
             "title": f.get("title", ""), "title_en": f.get("title_en", f.get("title", ""))}
            for f in findings]


async def run_once() -> dict:
    """Egy újraellenőrzési kör: az aktív (még sebezhető) célpontok újraszkennelése."""
    now = _now()
    st = load_state()
    targets = st.setdefault("targets", {})
    # új találatos célpontok felvétele (a javultakat NEM élesztjük újra)
    for tgt in _hit_targets():
        if tgt not in targets:
            targets[tgt] = {"first_seen": now, "status": "vulnerable", "findings": [],
                            "checks": 0, "last_check": None, "fixed_at": None}
    active = [t for t, d in targets.items() if d.get("status") == "vulnerable"]
    sem = asyncio.Semaphore(_CONCURRENCY)

    async def one(tgt: str):
        async with sem:
            try:
                r = await scanner.scan(tgt, extended=True)
                return tgt, r.get("findings", []), bool(r.get("resolved"))
            except Exception:  # noqa: BLE001
                return tgt, None, False

    for tgt, findings, resolved in await asyncio.gather(*(one(t) for t in active)):
        d = targets[tgt]
        d["last_check"] = now
        d["checks"] = d.get("checks", 0) + 1
        if findings is None:
            continue                      # hiba/elérhetetlen: hagyjuk aktívnak, később újra
        if findings:
            d["status"] = "vulnerable"
            d["findings"] = _finds(findings)
        else:
            d["status"] = "fixed"         # eltűnt a találat → javítva, és NEM próbáljuk újra
            d["fixed_at"] = now
    st["last_run"] = now
    st["generated"] = now
    save_state(st)
    return summary(st)


def summary(st: dict | None = None) -> dict:
    st = st if st is not None else load_state()
    targets = st.get("targets", {})
    watched, fixed = [], []
    for t, d in targets.items():
        if d.get("status") == "fixed":
            fixed.append({"target": t, "fixed_at": d.get("fixed_at"),
                          "findings": d.get("findings", []), "checks": d.get("checks", 0)})
        else:
            watched.append({"target": t, "findings": d.get("findings", []),
                            "last_check": d.get("last_check"), "checks": d.get("checks", 0)})
    fixed.sort(key=lambda x: x.get("fixed_at") or "", reverse=True)
    watched.sort(key=lambda x: x.get("target") or "")
    return {"enabled": ENABLED, "hours": HOURS, "last_run": st.get("last_run"),
            "watched": len(watched), "fixed": len(fixed),
            "watched_list": watched, "fixed_list": fixed}


async def loop() -> None:
    """Háttér-ciklus: a perzisztens last_run alapján nem fut feleslegesen újraindításkor."""
    while True:
        wait = seconds_until_due()
        if wait > 0:
            await asyncio.sleep(min(wait, 3600))
            continue
        try:
            await run_once()
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(HOURS * 3600)
