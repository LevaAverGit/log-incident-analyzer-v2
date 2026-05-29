from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml

_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "default_rules.yml"

_DEFAULT: Dict[str, Any] = {
    "ssh_brute_force": {
        "min_attempts": 10,
        "medium_threshold": 30,
        "high_threshold": 100,
    },
    "web_scanning": {
        "min_404_count": 30,
        "high_threshold": 80,
    },
    "repeated_auth_errors": {
        "min_count": 20,
        "high_threshold": 50,
    },
    "scoring": {
        "multi_indicator_bonus": 20,
        "max_score": 100,
    },
}


def load_config(path: str = None) -> Dict[str, Any]:
    """Load YAML config. Falls back to built-in defaults if file is missing."""
    target = Path(path) if path else _DEFAULT_CONFIG_PATH
    if target.exists():
        with open(target) as f:
            data = yaml.safe_load(f)
        if data:
            return data
    return _DEFAULT
