BLACKNET-HUB

Unified CLI-Based SOC Platform (Blue Team / Defense Engineering Project)

BLACKNET-HUB is a command-line Security Operations Center (SOC) platform built in Python.
It correlates security telemetry from multiple engines, scores incidents, maps MITRE ATT&CK techniques, generates response guidance, and provides a full investigation workflow — entirely from the terminal.

This project simulates how a real SOC works internally — without relying on third-party SaaS tools.


---

🧠 Project Architecture

BLACKNET-HUB integrates multiple security engines into one system:

Engine	Purpose

Sentinel-XDR	Detection engine (logs, alerts, behavior rules)
Nexus-Auditor	Network exposure and surface analysis
Threat-Intel Engine	IOC & reputation correlation
Forensic-X	Credential abuse, admin misuse, timeline reconstruction
BLACKNET-HUB	Correlator, risk score engine, MITRE mapping, response & dashboard



---

✅ Features

🔍 Detection & Correlation

Ingests multiple JSON data sources

Builds incidents automatically

Combines:

alerts

forensic data

threat intelligence

network exposure


Computes final risk score



---

🧭 MITRE ATT&CK Mapping

Every incident is mapped to:

MITRE technique ID (example: T1059)

Tactic name (Execution, Persistence, etc)

Description


Example:

MITRE: T1059 — Execution
Command execution / reverse shell activity


---

🧮 SOC Metrics & Analytics

Command:

python -m cli.stats

Outputs:

Incident count

Severity distribution

Risk distribution

MITRE usage statistics

Most risky users

Lifecycle state counts



---

🧑‍💻 Incident Lifecycle Engine

Command:

python -m cli.incidents

Supported operations:

Set status:

NEW

TRIAGED

CONTAINED

ERADICATED

CLOSED


Assign owner

Add analyst notes


Example:

python -m cli.incidents --id INC_0002 --set-status TRIAGED --owner vikas --note "Initial review done"


---

🔎 Threat Hunting Mode

Command examples:

python -m cli.hunt --user root
python -m cli.hunt --mitre T1059
python -m cli.hunt --category MALICIOUS_PATTERN
python -m cli.hunt --min-risk 50

This enables proactive investigation beyond alerts.


---

🛡 Defense Playbook Engine

Generate structured response guidance per incident:

python -m cli.defense --id INC_0002

Example output:

PHASE: CONTAINMENT
- Block C2 connections
- Lock account
- Kill malicious sessions

PHASE: ERADICATION
- Review cron jobs
- Inspect services

PHASE: RECOVERY
- Reset credentials
- Restore access

PHASE: FORENSIC
- Preserve logs
- Capture system state

Commands are printed only — never auto-executed.


---

🖥 TUI Dashboard (CLI SOC Console)

Command:

python -m cli.dashboard

Features:

Live incident list

Severity coloring

Defense toggle view (press D)

Status & owner display

Summary metrics

Timeline view


Controls:

↑ / ↓   Navigate incidents
D       Toggle Defense View
R       Refresh
Q       Quit


---

🧾 Report Export

Generate SOC-style report:

python -m cli.hub --output-html reports/blacknet-report.html

Includes:

Incident summary

Risk scores

MITRE mapping

Automated defense suggestions



---

🧩 Directory Structure

blacknet-hub/
├── cli/
│   ├── dashboard.py
│   ├── incidents.py
│   ├── hunt.py
│   ├── defense.py
│   └── stats.py
|
├── core/
│   ├── correlator.py
│   ├── playbook.py
│   ├── incident_store.py
│   ├── response.py
│   ├── dashboard_ui.py
│   └── report.py
|
├── data/
│   └── incidents_state.json
|
├── reports/
│   └── blacknet-report.html
|
└── README.md


---

🎯 Why This Project Exists

This project was built to understand how:

SIEM engines work internally

Alerts become incidents

Risk scoring is calculated

Analysts perform triage

Response actions are generated

MITRE ATT&CK is applied in practice

A SOC console could exist without enterprise tools



---

⚠️ Safety Notice

BLACKNET-HUB is:

Defensive only

Educational & engineering-focused

No attack automation

No malware

No scanning outside test systems

No self-executing commands


All commands are printed as recommendations only.


---

🏆 Skills Demonstrated

Python software engineering

SOC architecture

Incident response design

MITRE ATT&CK mapping

Risk analysis

CLI dashboards

Forensics logic

Defensive automation

Threat hunting workflows

Correlation engines



---

🧠 Author Notes

This project is not a toy.
It reflects how real SOC systems reason internally.

The goal was to:

> build a security platform from scratch — not just run tools.
