"""Authentication helpers — password hashing + Flask-Login user adapter.

Keeps web-framework auth concerns in the backend so the shared `core.User`
model stays framework-agnostic (it only stores `password_hash`).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from core.db import session_scope
from core.models import User


class AuthUser(UserMixin):
    """Lightweight Flask-Login principal wrapping a `core.User` row."""

    def __init__(self, user_id: int, username: str, role: str) -> None:
        self.id = user_id
        self.username = username
        self.role = role

    def get_id(self) -> str:  # Flask-Login stores this in the session
        return str(self.id)

    def to_dict(self) -> dict:
        return {"id": self.id, "username": self.username, "role": self.role}


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def create_user(username: str, password: str, role: str = "analyst") -> int:
    """Create a user; returns the new id. Raises ValueError if username exists."""
    with session_scope() as session:
        existing = session.query(User).filter(User.username == username).first()
        if existing is not None:
            raise ValueError(f"user '{username}' already exists")
        user = User(username=username, password_hash=hash_password(password), role=role)
        session.add(user)
        session.flush()
        return user.id


def authenticate(username: str, password: str) -> Optional[AuthUser]:
    """Validate credentials; updates last_login on success."""
    with session_scope() as session:
        user = session.query(User).filter(User.username == username).first()
        if user is None or not user.is_active:
            return None
        if not check_password_hash(user.password_hash, password):
            return None
        user.last_login = datetime.now(timezone.utc)
        return AuthUser(user.id, user.username, user.role)


def load_user(user_id: str) -> Optional[AuthUser]:
    """Flask-Login user_loader callback."""
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return None
    with session_scope() as session:
        user = session.get(User, uid)
        if user is None or not user.is_active:
            return None
        return AuthUser(user.id, user.username, user.role)
