from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Session

from src.api.config import settings


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""
    pass


_engine = None
_SessionLocal: Optional[sessionmaker] = None

# Initialize the engine only if DATABASE_URL is provided.
if settings.DATABASE_URL:
    _engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)
    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)


def get_engine():
    """Get the SQLAlchemy engine if configured."""
    return _engine


def get_session_factory():
    """Get the SQLAlchemy session factory if configured."""
    return _SessionLocal


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Provide a transactional scope around a series of operations."""
    if _SessionLocal is None:
        raise RuntimeError(
            "DATABASE_URL is not configured. Set DATABASE_URL in the backend .env file."
        )
    session = _SessionLocal()  # type: ignore[call-arg]
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
