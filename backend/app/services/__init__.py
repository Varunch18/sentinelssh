"""Service layer — business logic + serialization over the repositories."""
from __future__ import annotations

import json
from typing import List


def parse_json_list(raw) -> List[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
        return value if isinstance(value, list) else []
    except (TypeError, ValueError):
        return []


def severity_for(score: int) -> str:
    if score > 70:
        return "high"
    if score > 30:
        return "medium"
    return "low"
