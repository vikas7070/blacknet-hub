import argparse
import curses

from core.loader import load_sentinel, load_nexus, load_intel, load_forensic
from core.correlator import unify
from core.dashboard_ui import run_dashboard


def main():
    parser = argparse.ArgumentParser(description="BLACKNET-HUB TUI Dashboard")
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

    curses.wrapper(run_dashboard, incidents)


if __name__ == "__main__":
    main()
