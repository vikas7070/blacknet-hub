from pathlib import Path
import yaml


def load_rules(path: str = "rules/forensic_rules.yaml") -> dict:
    """
    Load MITRE / detection rule mappings from YAML.
    """
    file = Path(path)
    if not file.exists():
        print(f"[WARN] Rule file not found: {file}")
        return {}

    with file.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return data or {}
