import argparse

from core.loader import load_sentinel, load_nexus, load_intel, load_forensic
from core.correlator import unify
from core.report import print_report
from core.timeline import build_events, print_timeline


def main():
    parser = argparse.ArgumentParser(description="BLACKNET HUB — unified SOC console")

    parser.add_argument("--sentinel", default="../sentinel-xdr/reports/sentinel-v2-report.json")
    parser.add_argument("--nexus", default="../nexus-auditor/reports/nexus-report.json")
    parser.add_argument("--intel", default="../threat-intel-engine/reports/intel-report.json")
    parser.add_argument("--forensic", default="../forensic-x/reports/forensic-report.json")
    parser.add_argument("--timeline-user", help="Show detailed timeline for this user")

    args = parser.parse_args()

    sentinel = load_sentinel(args.sentinel)
    nexus = load_nexus(args.nexus)
    intel = load_intel(args.intel)
    forensic = load_forensic(args.forensic)

    unified = unify(sentinel, nexus, intel, forensic, [])
    print_report(unified)

    if args.timeline_user:
        events = build_events(sentinel, forensic)
        print_timeline(events, args.timeline_user)


if __name__ == "__main__":
    main()
