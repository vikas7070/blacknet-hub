from core.response import suggest_actions
from core.incident_store import get_record


def print_report(unified):
    print("\n=== BLACKNET HUB — UNIFIED SOC VIEW ===\n")

    if not unified:
        print("No incidents found.")
        return

    for i in unified:
        inc_id = i["id"]
        rec = get_record(inc_id)  # do not auto-create
        status = rec.get("status") if rec else "NEW"
        owner = rec.get("owner") if rec else None

        print(f"[{inc_id}] {i['title']}")
        print(f"  Status   : {status}" + (f" (owner={owner})" if owner else ""))
        print(f"  Severity : {i['severity']}")
        print(f"  Risk     : {i['risk']} (final={i.get('final_risk')})")
        print(f"  User     : {i['user']}")
        print(f"  IP       : {i['ip']}")

        # Nexus
        if i.get("nexus"):
            print("  [NEXUS]    Attack Surface:", i["nexus"].get("attack_surface_score"))
        else:
            print("  [NEXUS]    No data")

        # Intel
        if i.get("intel"):
            print("  [INTEL]    Risk:", i["intel"].get("risk"),
                  "Score:", i["intel"].get("score"))
        else:
            print("  [INTEL]    No IOC match")

        # Forensic-X + MITRE
        if i.get("forensic"):
            print("  [FORENSIC] Risk:", i["forensic"].get("risk_score"))

            findings = i["forensic"].get("findings", []) or []
            categories = sorted(
                {f.get("category") for f in findings if f.get("category")}
            )
            print("            Categories:", categories)

            mitre = i.get("mitre")
            if mitre:
                print(f"  [MITRE]   {mitre.get('mitre_id')} — {mitre.get('tactic')}")
                desc = mitre.get("description")
                if desc:
                    print(f"           {desc}")
        else:
            print("  [FORENSIC] No suspicious behavior")

        # Response suggestions
        actions = suggest_actions(i)
        if actions:
            print("  [RESPONSE] Suggested actions:")
            for a in actions:
                print(f"    - {a}")

        print("-" * 75)
