"""Pydantic schemas for incident queries and responses."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.attack import MitreOut

ALLOWED_STATUS = {"open", "triaged", "closed"}


class IncidentQuery(BaseModel):
    model_config = ConfigDict(extra="ignore")

    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=25, ge=1, le=100)
    status: Optional[str] = None
    source_ip: Optional[str] = None
    min_risk: Optional[int] = Field(default=None, ge=0, le=100)
    sort: str = "last_seen"
    order: str = "desc"

    @field_validator("status")
    @classmethod
    def _validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.lower()
        if v not in ALLOWED_STATUS:
            raise ValueError(f"status must be one of {sorted(ALLOWED_STATUS)}")
        return v

    @field_validator("sort")
    @classmethod
    def _validate_sort(cls, v: str) -> str:
        allowed = {"last_seen", "first_seen", "max_risk_score", "attempt_count"}
        if v not in allowed:
            raise ValueError(f"sort must be one of {sorted(allowed)}")
        return v

    @field_validator("order")
    @classmethod
    def _validate_order(cls, v: str) -> str:
        v = (v or "desc").lower()
        if v not in {"asc", "desc"}:
            raise ValueError("order must be 'asc' or 'desc'")
        return v


class RelatedAttackOut(BaseModel):
    id: int
    timestamp: Optional[datetime]
    username: Optional[str]
    password: Optional[str]
    risk_score: int
    risk_level: str


class IncidentOut(BaseModel):
    """Incident card summary."""

    id: int
    source_ip: str
    country: Optional[str]
    title: Optional[str]
    severity: str
    max_risk_score: int
    attempt_count: int
    status: str
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    mitre: List[MitreOut] = []


class IncidentDetailOut(IncidentOut):
    """Full incident with related attacks + aggregated behaviours."""

    behaviors: List[str] = []
    related_attacks: List[RelatedAttackOut] = []
