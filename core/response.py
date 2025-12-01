from typing import List, Dict, Any


def suggest_actions(incident: Dict[str, Any]) -> List[str]:
    """
    Safe response engine:
    Works even if forensic data is missing.
    """
    actions: List[str] = []

    severity = (incident.get("severity") or "").upper()
    final_risk = incident.get("final_risk") or 0
    mitre = incident.get("mitre") or {}

    forensic = incident.get("forensic") or {}
    findings = forensic.get("findings") or []
    categories = {f.get("category") for f in findings if isinstance(f, dict)}

    # Risk-based response
    if final_risk >= 90 or severity == "CRITICAL":
        actions.append("Immediately isolate affected host or account.")
        actions.append("Escalate to incident response team.")
    elif final_risk >= 70:
        actions.append("Prioritize investigation within this shift.")
        actions.append("Increase monitoring for related accounts and IPs.")
    elif final_risk >= 40:
        actions.append("Schedule follow-up review and increase logging for this entity.")

    # Category-based actions
    if "CREDENTIAL_ABUSE" in categories:
        actions.append("Force password reset for the user and invalidate active sessions.")
        actions.append("Enforce or verify MFA on this account.")

    if "ADMIN_MISUSE" in categories:
        actions.append("Audit recent privileged commands and changes (cron/services/users).")
        actions.append("Review admin group membership and remove unnecessary privileges.")

    if "MALICIOUS_PATTERN" in categories:
        actions.append("Block outbound connections to suspicious destinations at firewall.")
        actions.append("Collect and preserve forensic artifacts (shell history, logs).")

    if "TIME_ANOMALY" in categories:
        actions.append("Verify whether off-hours activity was authorized.")
        actions.append("Enable alerts for future off-hours actions for this user.")

    # MITRE-based actions
    tech = mitre.get("mitre_id")
    if tech == "T1059":
        actions.append("Harden script execution policies and restrict unnecessary interpreters.")
    if tech == "T1078":
        actions.append("Review all recent successful logins for this user from unusual IPs.")
    if tech == "T1547":
        actions.append("Inspect persistence mechanisms (cron, system services) for backdoors.")
    if tech == "T1087":
        actions.append("Reduce user visibility and tighten enumeration paths.")

    # Deduplicate
    clean = []
    for a in actions:
        if a not in clean:
            clean.append(a)

    return clean
