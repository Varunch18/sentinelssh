"""Pydantic schemas for attack queries and responses."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

ALLOWED_SORT_FIELDS = {
    "timestamp", "risk_score", "source_ip", "country", "username", "duration",
}
ALLOWED_RISK_LEVELS = {"low", "medium", "high"}


class AttackQuery(BaseModel):
    """Validated query parameters for listing/filtering attacks."""

    model_config = ConfigDict(extra="ignore")

    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=25, ge=1, le=100)
    sort: str = "timestamp"
    order: str = "desc"

    # Filters
    source_ip: Optional[str] = None
    country: Optional[str] = None
    username: Optional[str] = None
    risk_level: Optional[str] = None
    min_risk: Optional[int] = Field(default=None, ge=0, le=100)
    max_risk: Optional[int] = Field(default=None, ge=0, le=100)
    is_malicious: Optional[bool] = None
    incident_id: Optional[int] = None

    # Date range
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None

    @field_validator("sort")
    @classmethod
    def _validate_sort(cls, v: str) -> str:
        if v not in ALLOWED_SORT_FIELDS:
            raise ValueError(f"sort must be one of {sorted(ALLOWED_SORT_FIELDS)}")
        return v

    @field_validator("order")
    @classmethod
    def _validate_order(cls, v: str) -> str:
        v = (v or "desc").lower()
        if v not in {"asc", "desc"}:
            raise ValueError("order must be 'asc' or 'desc'")
        return v

    @field_validator("risk_level")
    @classmethod
    def _validate_level(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.lower()
        if v not in ALLOWED_RISK_LEVELS:
            raise ValueError(f"risk_level must be one of {sorted(ALLOWED_RISK_LEVELS)}")
        return v


class CommandOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    timestamp: Optional[datetime] = None
    command: str
    command_type: str


class MitreOut(BaseModel):
    id: str
    name: str
    tactic: str
    url: str = ""


class AttackOut(BaseModel):
    """Serialized attack record."""

    id: int
    timestamp: Optional[datetime]
    source_ip: str
    source_port: Optional[int]
    country: Optional[str]
    asn: Optional[str]
    isp: Optional[str]
    username: Optional[str]
    password: Optional[str]
    ssh_version: Optional[str]
    duration: float
    auth_attempts: int
    risk_score: int
    risk_level: str
    is_malicious: bool
    reputation: Optional[int]
    behaviors: List[str] = []
    mitre: List[MitreOut] = []
    incident_id: Optional[int] = None
    command_count: int = 0
    commands: Optional[List[CommandOut]] = None
