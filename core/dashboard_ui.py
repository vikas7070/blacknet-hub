from __future__ import annotations

import curses
from typing import List, Dict, Any

from core.response import suggest_actions
from core.incident_store import get_record
from core.playbook import build_playbook


SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def _severity_label(inc: Dict[str, Any]) -> str:
    sev = (inc.get("severity") or "").upper()
    if sev == "CRITICAL" or (inc.get("final_risk", 0) >= 90):
        return "CRIT"
    if sev == "HIGH":
        return "HIGH"
    if sev == "MEDIUM":
        return "MED"
    return "LOW"


def _short_status(inc: Dict[str, Any]) -> str:
    st = (inc.get("status") or "NEW").upper()
    if st.startswith("TRI"):
        return "TRIA"
    if st.startswith("CONTAINED"):
        return "CONT"
    if st.startswith("ERADICATED"):
        return "ERAD"
    if st.startswith("CLOSED"):
        return "CLSD"
    return st[:4]


def _sort_incidents(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def key(i: Dict[str, Any]):
        sev = (i.get("severity") or "").upper()
        return (
            -SEVERITY_ORDER.get(sev, 0),
            -(i.get("final_risk") or 0),
        )

    return sorted(incidents, key=key)


def _draw_header(stdscr, incidents: List[Dict[str, Any]]):
    h, w = stdscr.getmaxyx()
    title = "BLACKNET-HUB — TUI SOC DASHBOARD"
    stdscr.addstr(0, max(0, (w - len(title)) // 2), title, curses.A_BOLD)

    total = len(incidents)
    crit = sum(1 for i in incidents if i.get("final_risk", 0) >= 90)
    high = sum(1 for i in incidents if 70 <= i.get("final_risk", 0) < 90)

    info = f"INCIDENTS: {total} | CRITICAL: {crit} | HIGH: {high}"
    stdscr.addstr(1, 2, info)

    stdscr.addstr(
        h - 2,
        2,
        "UP/DOWN: select  |  D: toggle detail/defense  |  R: refresh  |  Q: quit",
        curses.A_DIM,
    )


def _draw_incident_list(stdscr, incidents: List[Dict[str, Any]], selected_idx: int):
    h, w = stdscr.getmaxyx()
    start_row = 3
    max_rows = h // 2 - 3

    stdscr.addstr(start_row, 2, "INCIDENTS", curses.A_UNDERLINE)
    start_row += 1

    header = f"{'ID':<9} {'ST':<5} {'SEV':<6} {'FINAL':<6} {'USER':<10} TITLE"
    stdscr.addstr(start_row, 2, header, curses.A_BOLD)
    start_row += 1

    view = incidents[:max_rows]

    for idx, inc in enumerate(view):
        is_sel = (idx == selected_idx)
        sev_label = _severity_label(inc)
        st_label = _short_status(inc)
        line = f"{str(inc.get('id')):<9} {st_label:<5} {sev_label:<6} {str(inc.get('final_risk', '')):<6} {str(inc.get('user') or ''):<10} {str(inc.get('title') or '')[:w-45]}"
        attr = curses.A_REVERSE if is_sel else curses.A_NORMAL

        if sev_label == "CRIT":
            attr |= curses.color_pair(1)
        elif sev_label == "HIGH":
            attr |= curses.color_pair(2)
        elif sev_label == "MED":
            attr |= curses.color_pair(3)

        stdscr.addstr(start_row + idx, 2, line.ljust(w - 4), attr)


def _draw_incident_detail(stdscr, incident: Dict[str, Any], defense_mode: bool):
    h, w = stdscr.getmaxyx()
    top = h // 2 + 1

    if defense_mode:
        stdscr.addstr(top, 2, "DEFENSE PLAYBOOK (summary)", curses.A_UNDERLINE)
        top += 1

        pb = build_playbook(incident)
        for phase in pb["phases"]:
            stdscr.addstr(top, 2, f"PHASE: {phase['name']}", curses.A_BOLD)
            top += 1
            if not phase["steps"]:
                stdscr.addstr(top, 4, "(no steps)")
                top += 1
                continue
            for step in phase["steps"]:
                title = step["title"][: w - 8]
                stdscr.addstr(top, 4, f"- {title}")
                top += 1
                if top >= h - 3:
                    return
        return

    # Normal detail / response mode
    stdscr.addstr(top, 2, "DETAIL / RESPONSE", curses.A_UNDERLINE)
    top += 1

    mitre = incident.get("mitre") or {}
    mitre_line = ""
    if mitre:
        mitre_line = f"{mitre.get('mitre_id')} — {mitre.get('tactic')}"

    forensic = incident.get("forensic") or {}
    findings = forensic.get("findings") or []
    cats = sorted({f.get("category") for f in findings if f.get("category")})

    state = incident.get("status") or "NEW"
    owner = incident.get("owner") or "-"

    lines = [
        f"User      : {incident.get('user')}",
        f"IP        : {incident.get('ip')}",
        f"Status    : {state} (owner={owner})",
        f"Severity  : {incident.get('severity')} (final={incident.get('final_risk')})",
        f"Categories: {', '.join(cats) if cats else 'None'}",
        f"MITRE     : {mitre_line or 'None'}",
    ]

    for l in lines:
        stdscr.addstr(top, 2, l[: w - 4])
        top += 1

    actions = suggest_actions(incident)
    stdscr.addstr(top, 2, "Suggested actions:", curses.A_BOLD)
    top += 1
    if not actions:
        stdscr.addstr(top, 4, "- None (low risk)")
        return

    for a in actions[: h - top - 2]:
        stdscr.addstr(top, 4, f"- {a[: w - 8]}")
        top += 1


def run_dashboard(stdscr, incidents: List[Dict[str, Any]]):
    curses.curs_set(0)
    curses.start_color()
    curses.init_pair(1, curses.COLOR_RED, 0)     # critical
    curses.init_pair(2, curses.COLOR_MAGENTA, 0) # high
    curses.init_pair(3, curses.COLOR_YELLOW, 0)  # medium

    # Enrich with status/owner from incident_store
    enriched: List[Dict[str, Any]] = []
    for inc in incidents:
        rec = get_record(inc["id"])
        status = (rec.get("status") if rec else "NEW") or "NEW"
        owner = rec.get("owner") if rec else None
        new_inc = dict(inc)
        new_inc["status"] = status
        new_inc["owner"] = owner
        enriched.append(new_inc)

    incidents_sorted = _sort_incidents(enriched)
    selected_idx = 0
    defense_mode = False

    while True:
        stdscr.erase()
        _draw_header(stdscr, incidents_sorted)

        if incidents_sorted:
            if selected_idx >= len(incidents_sorted):
                selected_idx = len(incidents_sorted) - 1
            _draw_incident_list(stdscr, incidents_sorted, selected_idx)
            _draw_incident_detail(stdscr, incidents_sorted[selected_idx], defense_mode)
        else:
            stdscr.addstr(4, 2, "No incidents to display.")

        stdscr.refresh()

        ch = stdscr.getch()
        if ch in (ord("q"), ord("Q")):
            break
        elif ch in (curses.KEY_UP, ord("k")):
            if selected_idx > 0:
                selected_idx -= 1
        elif ch in (curses.KEY_DOWN, ord("j")):
            if selected_idx < len(incidents_sorted) - 1:
                selected_idx += 1
        elif ch in (ord("r"), ord("R")):
            break  # caller will re-run dashboard with fresh data
        elif ch in (ord("d"), ord("D")):
            defense_mode = not defense_mode
