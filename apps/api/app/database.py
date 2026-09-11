"""
Database Session & Connection Management Module
Provides SQLAlchemy engine creation, session factory, base model, and FastAPI dependency.
"""

import logging
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.config import settings

logger = logging.getLogger(__name__)

# Determine active database URL (with SQLite fallback if PostgreSQL is unconfigured or in tests)
db_url = settings.DATABASE_URL
connect_args = {}

if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

# Create primary SQLAlchemy engine
try:
    engine = create_engine(
        db_url,
        connect_args=connect_args,
        pool_pre_ping=True,
    )
except Exception as e:
    logger.warning("Could not initialize database engine with %s: %s. Using SQLite fallback.", db_url, e)
    db_url = settings.SQLITE_DATABASE_URL
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
    )

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative Base for models
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency yielding a thread-local database session.
    Ensures rollback on unhandled exceptions and guaranteed session closure.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_database_connection() -> bool:
    """
    Diagnostic helper to test whether the active database engine is reachable.
    Returns True if reachable, False otherwise.
    """
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            return True
    except Exception as exc:
        logger.debug("Database connectivity check failed: %s", exc)
        return False
