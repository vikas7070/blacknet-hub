import argparse
import json

from core.incident_store import list_incidents, update_incident


def main():
    parser = argparse.ArgumentParser(description="BLACKNET Incident Lifecycle CLI")
    parser.add_argument("--list", action="store_true", help="List all tracked incidents")
    parser.add_argument("--id", help="Incident ID (e.g. INC_0002) to update")
    parser.add_argument("--set-status", help="Set status: NEW/TRIAGED/CONTAINED/ERADICATED/CLOSED")
    parser.add_argument("--owner", help="Set or change owner (e.g. vikas)")
    parser.add_argument("--note", help="Add a note/comment to this incident")
    args = parser.parse_args()

    if args.list:
        incs = list_incidents()
        if not incs:
            print("No incident state recorded yet.")
            return
        for rec in sorted(incs, key=lambda r: r.get("id", "")):
            print(
                f"{rec.get('id')}  "
                f"status={rec.get('status')}  "
                f"owner={rec.get('owner')}  "
                f"updated={rec.get('updated_at')}"
            )
        return

    if not args.id:
        parser.error("--id is required when updating an incident")

    rec = update_incident(
        args.id,
        status=args.set_status,
        owner=args.owner,
        note=args.note,
    )
    print(json.dumps(rec, indent=2))


if __name__ == "__main__":
    main()
