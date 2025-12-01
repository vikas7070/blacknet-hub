import json
from pathlib import Path


def load_json(path: str):
    p = Path(path)
    if not p.exists():
        print(f"[WARN] File not found: {path}")
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load {path}: {e}")
        return {}


def load_sentinel(path):
    return load_json(path)


def load_nexus(path):
    return load_json(path)


def load_intel(path):
    return load_json(path)


def load_forensic(path):
    return load_json(path)


def load_websec(path):
    data = load_json(path)
    return data if isinstance(data, list) else []
