from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from src.api.config import settings
from src.api.db import get_session_factory, session_scope, Base, get_engine
from src.api.models import LocalUser
from src.api.schemas import (
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    TokenResponse,
    UserOut,
)

router = APIRouter(prefix="/auth", tags=["Auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _create_jwt_token(subject: str, expires_delta: timedelta) -> str:
    """Create a JWT token for the given subject."""
    if not settings.JWT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT secret not configured. Please set JWT_SECRET environment variable.",
        )
    now = datetime.now(tz=timezone.utc)
    payload = {"sub": subject, "iat": int(now.timestamp()), "exp": int((now + expires_delta).timestamp())}
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return token


def _get_access_token(user_id: str) -> str:
    return _create_jwt_token(user_id, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))


def _get_refresh_token(user_id: str) -> str:
    return _create_jwt_token(user_id, timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES))


def _set_refresh_cookie(resp: Response, token: str):
    """Set HttpOnly refresh token cookie."""
    resp.set_cookie(
        key=settings.REFRESH_TOKEN_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,  # 'lax' recommended
        domain=settings.COOKIE_DOMAIN,
        max_age=int(timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES).total_seconds()),
        path="/",
    )


def _clear_refresh_cookie(resp: Response):
    resp.delete_cookie(
        key=settings.REFRESH_TOKEN_COOKIE_NAME,
        domain=settings.COOKIE_DOMAIN,
        path="/",
    )


def _verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def _hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _init_db():
    """Create tables if not exist (for local auth table)."""
    engine = get_engine()
    if engine is not None:
        Base.metadata.create_all(bind=engine)


def _get_db() -> Session:
    sf = get_session_factory()
    if sf is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not configured. Set DATABASE_URL environment variable.",
        )
    return sf()  # type: ignore[call-arg]


# PUBLIC_INTERFACE
@router.post(
    "/register",
    response_model=TokenResponse,
    summary="Register a new user",
    description="Creates a new user with email and password, stores hashed password, and returns an access token.",
    responses={
        201: {"description": "User registered"},
        400: {"description": "Email already registered"},
        500: {"description": "Server configuration error"},
    },
)
def register(payload: RegisterRequest, response: Response) -> TokenResponse:
    """
    Register a user with email and password.

    Parameters:
      - payload: RegisterRequest with email, password, and optional display_name

    Returns:
      - TokenResponse with access_token and token_type
    """
    _init_db()
    with session_scope() as db:
        existing = db.query(LocalUser).filter(LocalUser.email == payload.email.lower()).first()
        if existing:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

        user = LocalUser(
            email=payload.email.lower(),
            display_name=payload.display_name,
            password_hash=_hash_password(payload.password),
        )
        db.add(user)
        db.flush()  # Ensure ID is generated

        access = _get_access_token(user.id)
        refresh = _get_refresh_token(user.id)
        _set_refresh_cookie(response, refresh)
        response.status_code = status.HTTP_201_CREATED
        return TokenResponse(access_token=access, token_type="bearer")


# PUBLIC_INTERFACE
@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login",
    description="Verifies credentials and returns a JWT access token. Also sets an HttpOnly refresh token cookie.",
    responses={
        200: {"description": "Login successful"},
        401: {"description": "Invalid credentials"},
        500: {"description": "Server configuration error"},
    },
)
def login(payload: LoginRequest, response: Response) -> TokenResponse:
    """
    Log in a user with email and password.

    Parameters:
      - payload: LoginRequest with email and password

    Returns:
      - TokenResponse with access_token and token_type
    """
    _init_db()
    with session_scope() as db:
        user = db.query(LocalUser).filter(LocalUser.email == payload.email.lower()).first()
        if not user or not _verify_password(payload.password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        access = _get_access_token(user.id)
        refresh = _get_refresh_token(user.id)
        _set_refresh_cookie(response, refresh)
        return TokenResponse(access_token=access, token_type="bearer")


def _decode_token(token: str) -> str:
    """Decode JWT and return subject (user_id)."""
    if not settings.JWT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT secret not configured. Please set JWT_SECRET environment variable.",
        )
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return str(sub)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


def _get_current_user(request: Request) -> LocalUser:
    """Extract and validate bearer token, returning the LocalUser."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = auth_header.split(" ", 1)[1].strip()
    user_id = _decode_token(token)

    sf = get_session_factory()
    if sf is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not configured. Set DATABASE_URL environment variable.",
        )

    with sf() as db:  # type: ignore[misc]
        user = db.get(LocalUser, user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user


# PUBLIC_INTERFACE
@router.get(
    "/me",
    response_model=UserOut,
    summary="Get current user",
    description="Returns the currently authenticated user's profile.",
)
def me(current_user: Annotated[LocalUser, Depends(_get_current_user)]) -> UserOut:
    """Return the profile of the currently authenticated user."""
    return UserOut(
        id=current_user.id,
        email=current_user.email,
        display_name=current_user.display_name,
        created_at=current_user.created_at,
    )


# PUBLIC_INTERFACE
@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout",
    description="Clears the HttpOnly refresh token cookie.",
)
def logout(response: Response) -> MessageResponse:
    """Log out current session by clearing the refresh token cookie."""
    _clear_refresh_cookie(response)
    return MessageResponse(message="Logged out")


# PUBLIC_INTERFACE
@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Exchanges a valid refresh token cookie for a new access token.",
    responses={401: {"description": "Invalid refresh token"}},
)
def refresh(request: Request) -> TokenResponse:
    """
    Refresh an access token using a valid refresh token stored in an HttpOnly cookie.

    Returns:
      - TokenResponse with a new access_token and token_type
    """
    cookie_name = settings.REFRESH_TOKEN_COOKIE_NAME
    token = request.cookies.get(cookie_name)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")

    user_id = _decode_token(token)
    access = _get_access_token(user_id)
    return TokenResponse(access_token=access, token_type="bearer")
