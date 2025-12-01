def print_report(unified):
    print("\n=== BLACKNET HUB — UNIFIED SOC VIEW ===\n")

    if not unified:
        print("No incidents found.")
        return

    for i in unified:
        print(f"[{i['id']}] {i['title']}")
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

        # Forensic-X
        if i.get("forensic"):
            print("  [FORENSIC] Risk:", i["forensic"].get("risk_score"))
            findings = i["forensic"].get("findings", [])
            categories = list({f["category"] for f in findings})
            print("            Categories:", categories)
        else:
            print("  [FORENSIC] No suspicious behavior")

        print("-" * 75)
