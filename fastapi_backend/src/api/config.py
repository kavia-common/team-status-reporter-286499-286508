import os
from typing import List, Optional

from pydantic import BaseModel


class Settings(BaseModel):
    """Application settings loaded from environment variables."""

    ENV: str = os.getenv("ENV", "development")
    # Database connection string for PostgreSQL (SQLAlchemy URL format)
    DATABASE_URL: Optional[str] = os.getenv("DATABASE_URL")
    # JWT settings
    JWT_SECRET: Optional[str] = os.getenv("JWT_SECRET")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    REFRESH_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES", "43200"))  # 30 days
    REFRESH_TOKEN_COOKIE_NAME: str = os.getenv("REFRESH_TOKEN_COOKIE_NAME", "refresh_token")
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    COOKIE_DOMAIN: Optional[str] = os.getenv("COOKIE_DOMAIN")
    COOKIE_SAMESITE: str = os.getenv("COOKIE_SAMESITE", "lax")  # lax, strict, none

    # CORS
    FRONTEND_ORIGIN: Optional[str] = os.getenv("FRONTEND_ORIGIN")
    ADDITIONAL_CORS_ORIGINS: Optional[str] = os.getenv("ADDITIONAL_CORS_ORIGINS")  # comma-separated

    APP_TITLE: str = os.getenv("APP_TITLE", "Team Status Reporter API")
    APP_DESCRIPTION: str = os.getenv(
        "APP_DESCRIPTION",
        "API for authentication and weekly status reporting features.",
    )
    APP_VERSION: str = os.getenv("APP_VERSION", "0.1.0")


def get_cors_origins(settings: Settings) -> List[str]:
    """Build allowed CORS origins list from env-configured values."""
    origins: List[str] = []
    if settings.FRONTEND_ORIGIN:
        origins.append(settings.FRONTEND_ORIGIN)
    if settings.ADDITIONAL_CORS_ORIGINS:
        extras = [o.strip() for o in settings.ADDITIONAL_CORS_ORIGINS.split(",") if o.strip()]
        origins.extend(extras)
    # Fallback for development if nothing provided (browser won't allow credentials with *)
    if not origins and settings.ENV == "development":
        origins = ["http://localhost:3000", "http://127.0.0.1:3000"]
    return origins


settings = Settings()
