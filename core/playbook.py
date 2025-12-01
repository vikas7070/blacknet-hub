from __future__ import annotations

from typing import Dict, Any, List


def _base_context(incident: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": incident.get("id"),
        "user": incident.get("user"),
        "ip": incident.get("ip"),
        "severity": incident.get("severity"),
        "final_risk": incident.get("final_risk"),
        "mitre": incident.get("mitre") or {},
    }


def _containment_steps(ctx: Dict[str, Any], categories, mitre_id) -> List[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []

    user = ctx.get("user")
    ip = ctx.get("ip")

    if ip:
        steps.append({
            "title": "Block suspected C2 / malicious IP",
            "description": f"Block outbound/inbound traffic to/from {ip} at firewall.",
            "commands": [
                f"iptables -A INPUT -s {ip} -j DROP",
                f"iptables -A OUTPUT -d {ip} -j DROP",
            ],
        })

    if user:
        steps.append({
            "title": f"Lock account {user}",
            "description": "Temporarily lock the compromised account during investigation.",
            "commands": [
                f"usermod -L {user}",
                f"passwd -l {user}",
            ],
        })

    if "CREDENTIAL_ABUSE" in categories:
        steps.append({
            "title": "Invalidate sessions and enforce MFA",
            "description": "Terminate active sessions for the user and enforce MFA on next login.",
            "commands": [
                "# terminate SSH sessions for user",
                f"pkill -KILL -u {user}" if user else "# pkill -KILL -u <user>",
            ],
        })

    if mitre_id == "T1059":
        steps.append({
            "title": "Block reverse shells / suspicious outbound ports",
            "description": "Harden egress firewall rules for shell-like traffic (nc, bash over TCP, etc).",
            "commands": [
                "# example: block outbound high-risk ports",
                "iptables -A OUTPUT -p tcp --dport 4444 -j DROP",
            ],
        })

    return steps


def _eradication_steps(ctx: Dict[str, Any], categories, mitre_id) -> List[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []

    if "ADMIN_MISUSE" in categories or "MALICIOUS_PATTERN" in categories:
        steps.append({
            "title": "Review and clean cron jobs",
            "description": "Look for suspicious cron entries that may provide persistence.",
            "commands": [
                "crontab -l",
                "ls -l /etc/cron*",
                "grep -R 'nc ' /etc/cron* || true",
            ],
        })

        steps.append({
            "title": "Inspect system services for backdoors",
            "description": "Review custom or recently modified services.",
            "commands": [
                "systemctl list-units --type=service",
                "journalctl -u <service_name>",
            ],
        })

    if "TIME_ANOMALY" in categories:
        steps.append({
            "title": "Correlate off-hours activity",
            "description": "Confirm whether off-hours actions were authorized and by whom.",
            "commands": [
                "grep 'Jan 10 03:' /var/log/auth.log || true",
            ],
        })

    return steps


def _recovery_steps(ctx: Dict[str, Any], categories, mitre_id) -> List[Dict[str, Any]]:
    user = ctx.get("user")
    steps: List[Dict[str, Any]] = []

    if user:
        steps.append({
            "title": f"Reset credentials for {user}",
            "description": "After containment and eradication, reset the account password and re-enable login.",
            "commands": [
                f"passwd {user}",
                f"usermod -U {user}",
            ],
        })

    steps.append({
        "title": "Re-baseline detection rules",
        "description": "Update and tune detection rules so this attack pattern is detected earlier next time.",
        "commands": [
            "# Update detection configs / rule packs in Sentinel/FORENSIC-X",
        ],
    })

    return steps


def _forensic_steps(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []

    steps.append({
        "title": "Preserve key logs",
        "description": "Copy relevant logs to a safe location for further analysis.",
        "commands": [
            "mkdir -p /var/ir/INC_XXXX",
            "cp /var/log/auth.log /var/ir/INC_XXXX/",
            "tar czf /var/ir/INC_XXXX/auth.tar.gz /var/ir/INC_XXXX/auth.log",
        ],
    })

    steps.append({
        "title": "Capture process and network snapshot",
        "description": "Capture current processes and network connections for deeper forensic work.",
        "commands": [
            "ps aux > /var/ir/INC_XXXX/ps.txt",
            "ss -plant > /var/ir/INC_XXXX/net.txt",
        ],
    })

    return steps


def build_playbook(incident: Dict[str, Any]) -> Dict[str, Any]:
    ctx = _base_context(incident)
    forensic = incident.get("forensic") or {}
    findings = forensic.get("findings", []) or []
    categories = {f.get("category") for f in findings if f.get("category")}
    mitre = incident.get("mitre") or {}
    mitre_id = mitre.get("mitre_id")

    phases = []

    phases.append({
        "name": "CONTAINMENT",
        "steps": _containment_steps(ctx, categories, mitre_id),
    })

    phases.append({
        "name": "ERADICATION",
        "steps": _eradication_steps(ctx, categories, mitre_id),
    })

    phases.append({
        "name": "RECOVERY",
        "steps": _recovery_steps(ctx, categories, mitre_id),
    })

    phases.append({
        "name": "FORENSIC",
        "steps": _forensic_steps(ctx),
    })

    return {
        "incident": ctx,
        "phases": phases,
    }
