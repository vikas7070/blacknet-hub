from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List, Optional
import json
from datetime import datetime

STATE_FILE = Path("data/incidents_state.json")
DEFAULT_STATE = "NEW"


def _now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def load_state() -> Dict[str, Any]:
    if not STATE_FILE.exists():
        return {}
    try:
        with STATE_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state: Dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with STATE_FILE.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def get_record(incident_id: str, create: bool = False) -> Optional[Dict[str, Any]]:
    state = load_state()
    rec = state.get(incident_id)
    if rec is None and create:
        rec = {
            "id": incident_id,
            "status": DEFAULT_STATE,
            "owner": None,
            "notes": [],
            "created_at": _now_iso(),
            "updated_at": _now_iso(),
        }
        state[incident_id] = rec
        save_state(state)
    return rec


def update_incident(
    incident_id: str,
    status: Optional[str] = None,
    owner: Optional[str] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    state = load_state()
    rec = state.get(incident_id)
    if rec is None:
        rec = {
            "id": incident_id,
            "status": DEFAULT_STATE,
            "owner": None,
            "notes": [],
            "created_at": _now_iso(),
        }

    if status:
        rec["status"] = status.upper()
    if owner is not None:
        rec["owner"] = owner
    if note:
        notes = rec.get("notes") or []
        notes.append({"at": _now_iso(), "text": note})
        rec["notes"] = notes

    rec["updated_at"] = _now_iso()
    state[incident_id] = rec
    save_state(state)
    return rec


def list_incidents() -> List[Dict[str, Any]]:
    st = load_state()
    return list(st.values())
