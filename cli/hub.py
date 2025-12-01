import argparse
from core.loader import load_sentinel, load_nexus, load_intel, load_forensic
from core.correlator import unify
from core.report import print_report


def main():
    p = argparse.ArgumentParser(description="BLACKNET HUB")

    p.add_argument("--sentinel", default="../sentinel-xdr/reports/sentinel-v2-report.json")
    p.add_argument("--nexus", default="../nexus-auditor/reports/nexus-report.json")
    p.add_argument("--intel", default="../threat-intel-engine/reports/intel-report.json")
    p.add_argument("--forensic", default="../forensic-x/reports/forensic-report.json")

    args = p.parse_args()

    sentinel = load_sentinel(args.sentinel)
    nexus = load_nexus(args.nexus)
    intel = load_intel(args.intel)
    forensic = load_forensic(args.forensic)

    unified = unify(sentinel, nexus, intel, forensic, [])
    print_report(unified)


if __name__ == "__main__":
    main()
