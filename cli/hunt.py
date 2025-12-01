import argparse

from core.loader import load_sentinel, load_nexus, load_intel, load_forensic
from core.correlator import unify


def main():
    parser = argparse.ArgumentParser(description="BLACKNET Threat Hunting CLI")
    parser.add_argument("--sentinel", default="../sentinel-xdr/reports/sentinel-v2-report.json")
    parser.add_argument("--nexus", default="../nexus-auditor/reports/nexus-report.json")
    parser.add_argument("--intel", default="../threat-intel-engine/reports/intel-report.json")
    parser.add_argument("--forensic", default="../forensic-x/reports/forensic-report.json")

    parser.add_argument("--user", help="Filter by user (e.g. root)")
    parser.add_argument("--ip", help="Filter by IP/host")
    parser.add_argument("--mitre", help="Filter by MITRE ID (e.g. T1059)")
    parser.add_argument("--category", help="Filter by forensic category (e.g. MALICIOUS_PATTERN)")
    parser.add_argument("--min-risk", type=int, default=0, help="Minimum final risk")

    args = parser.parse_args()

    sentinel = load_sentinel(args.sentinel)
    nexus = load_nexus(args.nexus)
    intel = load_intel(args.intel)
    forensic = load_forensic(args.forensic)

    incidents = unify(sentinel, nexus, intel, forensic, [])

    matched = []
    for inc in incidents:
        if args.user and (inc.get("user") != args.user):
            continue
        if args.ip and (inc.get("ip") != args.ip):
            continue

        if args.mitre:
            m = inc.get("mitre") or {}
            if m.get("mitre_id") != args.mitre:
                continue

        if args.category:
            fx = inc.get("forensic") or {}
            findings = fx.get("findings", []) or []
            cats = {f.get("category") for f in findings if f.get("category")}
            if args.category not in cats:
                continue

        if (inc.get("final_risk") or 0) < args.min_risk:
            continue

        matched.append(inc)

    if not matched:
        print("No incidents matched the hunt criteria.")
        return

    print(f"=== HUNT RESULTS (count={len(matched)}) ===\n")
    for i in matched:
        mitre = i.get("mitre") or {}
        mitre_str = mitre.get("mitre_id") or "-"
        print(
            f"{i['id']}: user={i.get('user')} ip={i.get('ip')} "
            f"sev={i.get('severity')} final_risk={i.get('final_risk')} mitre={mitre_str}"
        )
