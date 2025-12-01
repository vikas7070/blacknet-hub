from pathlib import Path
from typing import List, Dict, Any
import html


def generate_html(unified: List[Dict[str, Any]], path: str) -> None:
    rows = []
    for inc in unified:
        mitre = inc.get("mitre") or {}
        mitre_str = ""
        if mitre:
            mitre_str = f"{mitre.get('mitre_id')} — {mitre.get('tactic')}"

        row = f"""
        <tr>
            <td>{html.escape(str(inc.get('id')))}</td>
            <td>{html.escape(str(inc.get('title') or ''))}</td>
            <td>{html.escape(str(inc.get('severity') or ''))}</td>
            <td>{html.escape(str(inc.get('final_risk') or ''))}</td>
            <td>{html.escape(str(inc.get('user') or ''))}</td>
            <td>{html.escape(str(inc.get('ip') or ''))}</td>
            <td>{html.escape(mitre_str)}</td>
        </tr>
        """
        rows.append(row)

    table_html = "\n".join(rows)

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>BLACKNET-HUB Incident Report</title>
<style>
body {{
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #05060a;
    color: #f5f5f5;
    padding: 20px;
}}
h1 {{
    text-align: center;
    margin-bottom: 10px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
    background: #0b0d15;
}}
th, td {{
    border: 1px solid #333;
    padding: 8px 10px;
    font-size: 14px;
}}
th {{
    background: #141825;
    text-align: left;
}}
tr:nth-child(even) {{
    background: #10131f;
}}
.badge {{
    display: inline-block;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 11px;
}}
.badge-high {{
    background: #b91c1c;
}}
.badge-medium {{
    background: #ca8a04;
}}
.badge-low {{
    background: #15803d;
}}
</style>
</head>
<body>
<h1>BLACKNET-HUB — Incident Summary</h1>
<p>Unified view from Sentinel-XDR, FORENSIC-X, Threat Intel Engine, and Nexus-Auditor.</p>
<table>
    <thead>
        <tr>
            <th>ID</th>
            <th>Title</th>
            <th>Severity</th>
            <th>Final Risk</th>
            <th>User</th>
            <th>IP</th>
            <th>MITRE</th>
        </tr>
    </thead>
    <tbody>
        {table_html}
    </tbody>
</table>
</body>
</html>
"""

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(doc, encoding="utf-8")
    print(f"[+] HTML report saved to {out.resolve()}")
