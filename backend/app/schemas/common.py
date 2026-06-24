"""Shared Pydantic query-parameter schemas (input validation)."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_PER_PAGE = 100


class PaginationParams(BaseModel):
    """Common pagination controls."""

    model_config = ConfigDict(extra="ignore")

    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=25, ge=1, le=MAX_PER_PAGE)


class DateRangeParams(BaseModel):
    model_config = ConfigDict(extra="ignore")

    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None


class TopParams(BaseModel):
    """Params for top-N aggregation endpoints."""

    model_config = ConfigDict(extra="ignore")

    limit: int = Field(default=10, ge=1, le=100)
    hours: Optional[int] = Field(default=None, ge=1, le=24 * 365)


class SortParams(BaseModel):
    model_config = ConfigDict(extra="ignore")

    sort: str = "timestamp"
    order: str = "desc"

    @field_validator("order")
    @classmethod
    def _validate_order(cls, v: str) -> str:
        v = (v or "desc").lower()
        if v not in {"asc", "desc"}:
            raise ValueError("order must be 'asc' or 'desc'")
        return v
