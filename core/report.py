def print_report(unified):
    print("\n=== BLACKNET HUB — UNIFIED SOC VIEW ===\n")

    if not unified:
        print("No incidents found.")
        return

    for i in unified:
        print(f"[{i['id']}] {i['title']}")
        print(f"  Severity : {i['severity']}")
        print(f"  Risk     : {i['risk']}")
        print(f"  User     : {i['user']}")
        print(f"  IP       : {i['ip']}")

        # Nexus
        if i["nexus"]:
            print("  [NEXUS]  Attack Surface:", i["nexus"].get("attack_surface_score"))
        else:
            print("  [NEXUS]  No data")

        # Intel
        if i["intel"]:
            print("  [INTEL]  Risk:", i["intel"].get("risk"), "Score:", i["intel"].get("score"))
        else:
            print("  [INTEL]  No IOC match")

        # Forensic
        if i["forensic"]:
            print("  [FORENSIC] Risk:", i["forensic"].get("risk_score"))
            cats = {f["category"] for f in i["forensic"].get("findings", [])}
            print("            Categories:", list(cats))
        else:
            print("  [FORENSIC] No suspicious behavior")

        print("-" * 70)
