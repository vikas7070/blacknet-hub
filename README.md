# BLACKNET HUB

Unified SOC console integrating:

- Sentinel-XDR
- Nexus-Auditor
- Threat Intel Engine
- FORENSIC-X

## Run:

```bash
python -m cli.hub

SAVE & EXIT.

---

# ✅ STEP 6 — Generate data from tools FIRST

Run these one by one:

```bash
# Sentinel
cd ~/sentinel-xdr
python -m cli.launch --log data/sample_auth.log --output-json reports/sentinel-v2-report.json

# Nexus
cd ~/nexus-auditor
python -m cli.audit --target 127.0.0.1 --output-json reports/nexus-report.json

# Threat Intel
cd ~/threat-intel-engine
python -m cli.ti --sentinel ../sentinel-xdr/reports/sentinel-v2-report.json --out reports/intel-report.json

# FORENSIC-X
cd ~/forensic-x
python -m cli.analyze --log data/sample.log --output-json reports/forensic-report.json

cd ~/blacknet-hub
python -m cli.hub
