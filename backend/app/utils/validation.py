"""Helpers for parsing/validating request query parameters via Pydantic."""
from __future__ import annotations

from typing import Type, TypeVar

from flask import request
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


def parse_args(model_cls: Type[T]) -> T:
    """Build a validated query model from request args.

    Pydantic ValidationError propagates to the global handler (422).
    """
    return model_cls(**request.args.to_dict())
