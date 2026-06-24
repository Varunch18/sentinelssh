"""Database engine + session management for SentinelSSH.

A single `DATABASE_URL` drives the dialect:
  * Development:  sqlite:///data/sentinelssh.sqlite3
  * Production:   postgresql+psycopg2://user:pass@host:5432/db

The engine is created lazily and cached so multiple importers (honeypot,
backend) share configuration without re-parsing the environment.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import BigInteger, Integer, MetaData, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DEFAULT_DATABASE_URL = "sqlite:///data/sentinelssh.sqlite3"

# Auto-incrementing primary key that works on both engines: BIGINT on
# PostgreSQL, INTEGER on SQLite (required for SQLite rowid auto-increment).
BigIntPK = BigInteger().with_variant(Integer(), "sqlite")

# Deterministic constraint names — required for Alembic batch migrations on
# SQLite (which recreate tables) and good practice everywhere.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base shared by all ORM models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


_engine: Optional[Engine] = None
_SessionFactory: Optional[sessionmaker] = None


def get_database_url() -> str:
    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


def get_engine(database_url: Optional[str] = None) -> Engine:
    """Return a cached SQLAlchemy engine, creating it on first use."""
    global _engine, _SessionFactory
    if _engine is not None and database_url is None:
        return _engine

    url = database_url or get_database_url()
    connect_args = {}
    if url.startswith("sqlite"):
        # SQLite must allow cross-thread use for the threaded honeypot.
        connect_args = {"check_same_thread": False}

    engine = create_engine(
        url,
        echo=False,
        future=True,
        pool_pre_ping=not url.startswith("sqlite"),
        connect_args=connect_args,
    )
    if database_url is None:
        _engine = engine
        _SessionFactory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    return engine


def get_session_factory() -> sessionmaker:
    if _SessionFactory is None:
        get_engine()
    assert _SessionFactory is not None  # for type-checkers
    return _SessionFactory


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope: commit on success, rollback on error, always close."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create all tables (used for dev/SQLite; production uses Alembic)."""
    from core import models  # noqa: F401 - ensure models are registered

    Base.metadata.create_all(bind=get_engine())
