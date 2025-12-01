from __future__ import annotations

from datetime import datetime
from typing import List, Dict, Any


def _parse_ts(ts: str | None):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def build_events(sentinel: dict, forensic: dict) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    # From Sentinel alerts
    for alert in sentinel.get("alerts", []):
        ts = alert.get("ts_first") or alert.get("ts_last")
        dt_ts = _parse_ts(ts)
        if not dt_ts:
            continue

        entity = alert.get("user") or alert.get("ip") or alert.get("asset")
        evidence_list = alert.get("event_samples") or []
        evidence = evidence_list[0] if evidence_list else ""

        events.append(
            {
                "ts": dt_ts,
                "entity": entity,
                "source": "sentinel-xdr",
                "severity": alert.get("severity"),
                "category": f"DETECTION:{alert.get('threat_id')}",
                "evidence": evidence,
            }
        )

    # From Forensic-X findings
    for u in forensic.get("users", []):
        user = u.get("user")
        for f in u.get("findings", []):
            ts = f.get("ts")
            dt_ts = _parse_ts(ts)
            if not dt_ts:
                continue

            events.append(
                {
                    "ts": dt_ts,
                    "entity": user,
                    "source": "forensic-x",
                    "severity": f.get("severity"),
                    "category": f.get("category"),
                    "evidence": f.get("evidence") or f.get("details", ""),
                }
            )

    events.sort(key=lambda e: e["ts"])
    return events


def print_timeline(events: List[Dict[str, Any]], entity: str) -> None:
    print(f"\n=== TIMELINE for {entity} ===\n")

    filtered = [e for e in events if e["entity"] == entity]
    if not filtered:
        print("No events found for this entity.")
        return

    for e in filtered:
        t_str = e["ts"].strftime("%Y-%m-%d %H:%M:%S")
        src = e.get("source")
        sev = e.get("severity")
        cat = e.get("category")
        ev = (e.get("evidence") or "")[:120]
        print(f"{t_str} [{src}/{sev}] {cat}")
        if ev:
            print(f"  {ev}")
