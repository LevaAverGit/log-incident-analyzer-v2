from __future__ import annotations

from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Finding

MULTI_INDICATOR_BONUS = 20
MAX_SCORE = 100


def score_to_severity(score: int) -> str:
    if score <= 20:
        return "Low"
    elif score <= 50:
        return "Medium"
    elif score <= 80:
        return "High"
    return "Critical"


def combine_incident_score(findings: List, cfg: Optional[Dict[str, Any]] = None) -> int:
    if not findings:
        return 0
    scoring_cfg = (cfg or {}).get("scoring", {}) if cfg else {}
    bonus = scoring_cfg.get("multi_indicator_bonus", MULTI_INDICATOR_BONUS)
    cap = scoring_cfg.get("max_score", MAX_SCORE)
    total = sum(f.score for f in findings)
    if len({f.finding_type for f in findings}) > 1:
        total += bonus
    return min(total, cap)


def calculate_incident_severity(findings: List, cfg: Optional[Dict[str, Any]] = None) -> str:
    return score_to_severity(combine_incident_score(findings, cfg))
