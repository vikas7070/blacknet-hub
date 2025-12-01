import argparse
import textwrap

from core.loader import load_sentinel, load_nexus, load_intel, load_forensic
from core.correlator import unify
from core.playbook import build_playbook


def print_playbook(pb: dict) -> None:
    inc = pb["incident"]
    print(f"=== DEFENSE PLAYBOOK — {inc.get('id')} ===")
    print(f"User     : {inc.get('user')}")
    print(f"IP       : {inc.get('ip')}")
    print(f"Severity : {inc.get('severity')} (final={inc.get('final_risk')})")
    mitre = inc.get("mitre") or {}
    if mitre:
        print(f"MITRE    : {mitre.get('mitre_id')} — {mitre.get('tactic')}")
    print()

    for phase in pb["phases"]:
        print(f"PHASE: {phase['name']}")
        if not phase["steps"]:
            print("  (no specific steps)")
            print()
            continue

        for idx, step in enumerate(phase["steps"], start=1):
            print(f"  {idx}. {step['title']}")
            if step.get("description"):
                wrapped = textwrap.wrap(step["description"], width=70)
                for line in wrapped:
                    print(f"     {line}")
            if step.get("commands"):
                print("     Commands:")
                for cmd in step["commands"]:
                    print(f"       $ {cmd}")
            print()
        print()


def main():
    parser = argparse.ArgumentParser(description="BLACKNET Defense Playbook CLI")
    parser.add_argument("--sentinel", default="../sentinel-xdr/reports/sentinel-v2-report.json")
    parser.add_argument("--nexus", default="../nexus-auditor/reports/nexus-report.json")
    parser.add_argument("--intel", default="../threat-intel-engine/reports/intel-report.json")
    parser.add_argument("--forensic", default="../forensic-x/reports/forensic-report.json")
    parser.add_argument("--id", required=True, help="Incident ID to generate playbook for (e.g. INC_0002)")
    args = parser.parse_args()

    sentinel = load_sentinel(args.sentinel)
    nexus = load_nexus(args.nexus)
    intel = load_intel(args.intel)
    forensic = load_forensic(args.forensic)

    incidents = unify(sentinel, nexus, intel, forensic, [])
    target = None
    for inc in incidents:
        if inc.get("id") == args.id:
            target = inc
            break

    if not target:
        print(f"No incident with id={args.id} found.")
        return

    pb = build_playbook(target)
    print_playbook(pb)


if __name__ == "__main__":
    main()
