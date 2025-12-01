def index_nexus(nexus):
    out = {}
    for asset in nexus.get("assets", []):
        ip = asset.get("ip")
        if ip:
            out[ip] = asset
    return out


def index_intel(intel):
    out = {}
    for rec in intel.get("indicators", []):
        out[rec.get("value")] = rec
    return out


def index_forensic(forensic):
    out = {}
    for u in forensic.get("users", []):
        out[u["user"]] = u
    return out


def unify(sentinel, nexus, intel, forensic, websec):
    nexus_by_ip = index_nexus(nexus)
    intel_by_ioc = index_intel(intel)
    forensic_by_user = index_forensic(forensic)

    unified = []

    for inc in sentinel.get("incidents", []):
        ent = inc.get("entities", {})
        user = ent.get("user")
        ip = ent.get("ip")

        unified.append({
            "id": inc.get("id"),
            "title": inc.get("title"),
            "severity": inc.get("severity"),
            "risk": inc.get("risk_score"),
            "user": user,
            "ip": ip,

            "nexus": nexus_by_ip.get(ip),
            "intel": intel_by_ioc.get(ip),
            "forensic": forensic_by_user.get(user),
        })

    unified.sort(key=lambda x: x.get("risk", 0), reverse=True)
    return unified
