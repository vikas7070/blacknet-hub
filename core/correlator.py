from core.rules import load_rules


def index_nexus(nexus: dict) -> dict:
    out = {}
    for asset in nexus.get("assets", []):
        ip = asset.get("ip")
        if ip:
            out[ip] = asset
    return out


def index_intel(intel: dict) -> dict:
    out = {}
    for rec in intel.get("indicators", []):
        val = rec.get("value")
        if val:
            out[val] = rec
    return out


def index_forensic(forensic: dict) -> dict:
    out = {}
    for u in forensic.get("users", []):
        name = u.get("user")
        if name:
            out[name] = u
    return out


def compute_final_risk(entry: dict) -> None:
    """
    Enterprise-grade scoring:
    - If FORENSIC risk >= 90 → final risk cannot go below 80
    - Otherwise weighted blend is used.
    final = 0.3*sentinel + 0.4*forensic + 0.2*intel + 0.1*nexus
    """
    base = entry.get("risk") or 0

    fx = entry.get("forensic") or {}
    ti = entry.get("intel") or {}
    nx = entry.get("nexus") or {}

    forensic_risk = fx.get("risk_score") or 0
    intel_score = ti.get("score") or 0
    nexus_score = nx.get("attack_surface_score") or 0

    weighted = (
        0.3 * base +
        0.4 * forensic_risk +
        0.2 * intel_score +
        0.1 * nexus_score
    )

    if forensic_risk >= 90:
        final = max(80, weighted)
    else:
        final = weighted

    entry["final_risk"] = int(final)


def unify(sentinel: dict, nexus: dict, intel: dict, forensic: dict, websec: list) -> list:
    nexus_by_ip = index_nexus(nexus)
    intel_by_ioc = index_intel(intel)
    forensic_by_user = index_forensic(forensic)
    rules = load_rules()

    unified = []

    for inc in sentinel.get("incidents", []):
        ent = inc.get("entities", {}) or {}
        user = ent.get("user")
        ip = ent.get("ip")

        item = {
            "id": inc.get("id"),
            "title": inc.get("title"),
            "severity": inc.get("severity"),
            "risk": inc.get("risk_score"),
            "user": user,
            "ip": ip,
            "nexus": nexus_by_ip.get(ip),
            "intel": intel_by_ioc.get(ip),
            "forensic": forensic_by_user.get(user),
        }

        # Choose strongest MITRE match from forensic findings
        mitre = None
        if item["forensic"]:
            findings = item["forensic"].get("findings", []) or []
            priority = ["MALICIOUS_PATTERN", "ADMIN_MISUSE", "CREDENTIAL_ABUSE", "TIME_ANOMALY"]
            for cat in priority:
                if any(f.get("category") == cat for f in findings):
                    mitre = rules.get(cat)
                    break
        item["mitre"] = mitre

        compute_final_risk(item)
        unified.append(item)

    unified.sort(key=lambda x: x.get("final_risk", 0), reverse=True)
    return unified
