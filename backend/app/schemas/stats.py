"""Pydantic schemas for stats / aggregation responses."""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel


class TopItem(BaseModel):
    value: str
    count: int


class TopMitreItem(BaseModel):
    id: str
    name: str
    tactic: str
    count: int


class RiskBucket(BaseModel):
    label: str
    count: int


class RiskDistribution(BaseModel):
    by_level: List[RiskBucket]
    by_bucket: List[RiskBucket]


class StatsOut(BaseModel):
    total_attacks: int
    total_incidents: int
    active_incidents: int
    critical_incidents: int
    high_risk_incidents: int
    unique_ips: int
    top_country: Optional[str]
    top_mitre: Optional[TopMitreItem]
    last_24h: int
