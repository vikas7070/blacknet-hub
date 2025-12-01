import argparse
from collections import Counter, defaultdict

from core.loader import load_sentinel, load_nexus, load_intel, load_forensic
from core.correlator import unify
from core.incident_store import get_record


def main():
    parser = argparse.ArgumentParser(description="BLACKNET SOC Metrics / Stats")
    parser.add_argument("--sentinel", default="../sentinel-xdr/reports/sentinel-v2-report.json")
    parser.add_argument("--nexus", default="../nexus-auditor/reports/nexus-report.json")
    parser.add_argument("--intel", default="../threat-intel-engine/reports/intel-report.json")
    parser.add_argument("--forensic", default="../forensic-x/reports/forensic-report.json")
    args = parser.parse_args()

    sentinel = load_sentinel(args.sentinel)
    nexus = load_nexus(args.nexus)
    intel = load_intel(args.intel)
    forensic = load_forensic(args.forensic)

    incidents = unify(sentinel, nexus, intel, forensic, [])

    if not incidents:
        print("No incidents to analyze.")
        return

    total = len(incidents)

    # Severity distribution
    sev_counter = Counter((i.get("severity") or "UNKNOWN").upper() for i in incidents)

    # Status distribution (from incident_store)
    status_counter = Counter()
    for i in incidents:
        rec = get_record(i["id"])
        st = (rec.get("status") if rec else "NEW") or "NEW"
        status_counter[st] += 1

    # Final risk bands
    bands = {
        "CRITICAL(>=90)": 0,
        "HIGH(70-89)": 0,
        "MEDIUM(40-69)": 0,
        "LOW(<40)": 0,
    }
    for i in incidents:
        r = i.get("final_risk") or 0
        if r >= 90:
            bands["CRITICAL(>=90)"] += 1
        elif r >= 70:
            bands["HIGH(70-89)"] += 1
        elif r >= 40:
            bands["MEDIUM(40-69)"] += 1
        else:
            bands["LOW(<40)"] += 1

    # MITRE usage
    mitre_counter = Counter()
    for i in incidents:
        mitre = i.get("mitre") or {}
        tid = mitre.get("mitre_id")
        if tid:
            mitre_counter[tid] += 1

    # Top users by cumulative final risk
    risk_by_user = defaultdict(int)
    for i in incidents:
        u = i.get("user") or "<unknown>"
        risk_by_user[u] += i.get("final_risk") or 0

    print("=== BLACKNET SOC STATS ===\n")
    print(f"Total incidents : {total}\n")

    print("By severity:")
    for sev, cnt in sev_counter.items():
        print(f"  {sev:<8} : {cnt}")
    print()

    print("By status (lifecycle):")
    for st, cnt in status_counter.items():
        print(f"  {st:<12} : {cnt}")
    print()

    print("By final risk band:")
    for band, cnt in bands.items():
        print(f"  {band:<16} : {cnt}")
    print()

    if mitre_counter:
        print("Top MITRE techniques:")
        for tid, cnt in mitre_counter.most_common():
            print(f"  {tid:<8} : {cnt}")
        print()
    else:
        print("No MITRE techniques recorded.\n")

    print("Top users by cumulative final risk:")
    for user, score in sorted(risk_by_user.items(), key=lambda kv: kv[1], reverse=True):
        print(f"  {user:<12} : {score}")
