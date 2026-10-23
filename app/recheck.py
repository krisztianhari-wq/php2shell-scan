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

ENABLED = os.environ.get("PHP2SHELL_RECHECK", "").lower() in ("1", "on", "true", "yes")
# Intervallum: PHP2SHELL_RECHECK_MINUTES dominál; különben a (régi) PHP2SHELL_RECHECK_HOURS * 60; alap 60 perc.
_MIN_ENV = os.environ.get("PHP2SHELL_RECHECK_MINUTES", "")
_HOURS_ENV = os.environ.get("PHP2SHELL_RECHECK_HOURS", "")
if _MIN_ENV.strip():
    INTERVAL_MIN = max(5, int(_MIN_ENV))
elif _HOURS_ENV.strip():
    INTERVAL_MIN = max(5, int(float(_HOURS_ENV) * 60))
else:
    INTERVAL_MIN = 60
HOURS = INTERVAL_MIN / 60.0   # visszafelé kompatibilis (a summary/őrláb ezt is közli)
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
    due = t + _dt.timedelta(minutes=INTERVAL_MIN)
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
    # a már javult (fixed) célpontokat békén hagyjuk; a sebezhetőket ÉS a (még figyelt) elérhetetleneket nézzük
    active = [t for t, d in targets.items() if d.get("status") in ("vulnerable", "unreachable")]
    sem = asyncio.Semaphore(_CONCURRENCY)

    async def one(tgt: str):
        async with sem:
            try:
                r = await scanner.scan(tgt, extended=True)
                return tgt, r.get("findings", []), bool(r.get("resolved")), bool(r.get("ports"))
            except Exception:  # noqa: BLE001
                return tgt, None, False, False

    for tgt, findings, resolved, responded in await asyncio.gather(*(one(t) for t in active)):
        d = targets[tgt]
        d["last_check"] = now
        d["checks"] = d.get("checks", 0) + 1
        if findings:
            # még/újra sebezhető
            d["status"] = "vulnerable"
            d["findings"] = _finds(findings)
            d["misses"] = 0
            d["unreachable_at"] = None
        elif findings is not None and resolved and responded:
            # feloldódik ÉS válaszol, de nincs találat → javítva (és NEM próbáljuk újra)
            d["status"] = "fixed"
            d["fixed_at"] = now
            d["misses"] = 0
            d["unreachable_at"] = None
        else:
            # nem oldódik fel / nem válaszol / belső hiba → elérhetetlen (tovább figyeljük, hátha visszajön)
            d["status"] = "unreachable"
            d["misses"] = d.get("misses", 0) + 1
            if not d.get("unreachable_at"):
                d["unreachable_at"] = now
    st["last_run"] = now
    st["generated"] = now
    save_state(st)
    return summary(st)


def summary(st: dict | None = None) -> dict:
    st = st if st is not None else load_state()
    targets = st.get("targets", {})
    watched, fixed, unreachable = [], [], []
    for t, d in targets.items():
        s = d.get("status")
        if s == "fixed":
            fixed.append({"target": t, "fixed_at": d.get("fixed_at"),
                          "findings": d.get("findings", []), "checks": d.get("checks", 0)})
        elif s == "unreachable":
            unreachable.append({"target": t, "findings": d.get("findings", []),
                                "unreachable_at": d.get("unreachable_at"), "misses": d.get("misses", 0),
                                "last_check": d.get("last_check")})
        else:
            watched.append({"target": t, "findings": d.get("findings", []),
                            "last_check": d.get("last_check"), "checks": d.get("checks", 0)})
    fixed.sort(key=lambda x: x.get("fixed_at") or "", reverse=True)
    unreachable.sort(key=lambda x: x.get("unreachable_at") or "", reverse=True)
    watched.sort(key=lambda x: x.get("target") or "")
    return {"enabled": ENABLED, "hours": HOURS, "interval_min": INTERVAL_MIN, "last_run": st.get("last_run"),
            "watched": len(watched), "fixed": len(fixed), "unreachable": len(unreachable),
            "watched_list": watched, "fixed_list": fixed, "unreachable_list": unreachable}


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
        await asyncio.sleep(INTERVAL_MIN * 60)
