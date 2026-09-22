"""
CyberForge — JWT Authentication Routes
Provides login, token refresh, and user management for analysts.

Features:
  • Login with username + password → returns JWT access + refresh token
  • Token refresh endpoint
  • Get current user profile (/api/auth/me)
  • Create analyst accounts (admin only)
  • Change password
  • Audit log on every login/logout
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.models import User, AuditLog

logger = logging.getLogger("cyberforge.auth")
router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# ── Crypto helpers ────────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.JWT_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


# ── Dependency: get current authenticated user ────────────────────────────────
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type", "access")
        if not username or token_type != "access":
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise credentials_exception
    return user


async def get_current_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


# ── Pydantic Schemas ──────────────────────────────────────────────────────────
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict


class RefreshRequest(BaseModel):
    refresh_token: str


class CreateUserRequest(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    role: str = "analyst"
    agency: str = ""
    badge_number: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class UserProfileResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: str
    role: str
    agency: str
    badge_number: Optional[str]
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]


# ── Audit logging helper ──────────────────────────────────────────────────────
def _audit(db: Session, action: str, actor: str, details: str = "", ip: str = ""):
    try:
        db.add(AuditLog(
            entity_type="auth",
            entity_id=actor,
            action=action,
            actor=actor,
            details=details,
            ip_address=ip,
        ))
        db.commit()
    except Exception as e:
        logger.warning(f"Audit log failed: {e}")


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """Authenticate and return JWT tokens."""
    user = db.query(User).filter(User.username == form_data.username).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        _audit(db, "login_failed", form_data.username, "Invalid credentials", request.client.host if request.client else "")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    access_token = create_access_token({"sub": user.username, "role": user.role})
    refresh_token = create_refresh_token({"sub": user.username})

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    db.commit()

    _audit(db, "login_success", user.username, f"Role: {user.role}", request.client.host if request.client else "")
    logger.info(f"User '{user.username}' logged in (role={user.role})")

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user={
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
            "agency": user.agency,
            "email": user.email,
        },
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(body: RefreshRequest, db: Session = Depends(get_db)):
    """Exchange a refresh token for a new access token."""
    try:
        payload = jwt.decode(body.refresh_token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        username = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    access_token = create_access_token({"sub": user.username, "role": user.role})
    new_refresh = create_refresh_token({"sub": user.username})

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh,
        user={"id": user.id, "username": user.username, "full_name": user.full_name, "role": user.role, "agency": user.agency, "email": user.email},
    )


@router.get("/me", response_model=UserProfileResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Return the currently authenticated user's profile."""
    return UserProfileResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        agency=current_user.agency,
        badge_number=current_user.badge_number,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
        last_login=current_user.last_login,
    )


@router.post("/users", status_code=201)
def create_user(
    body: CreateUserRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    """Create a new analyst account (admin only)."""
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        username=body.username,
        email=body.email,
        full_name=body.full_name,
        hashed_password=get_password_hash(body.password),
        role=body.role,
        agency=body.agency,
        badge_number=body.badge_number,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info(f"Admin '{current_user.username}' created user '{body.username}' (role={body.role})")
    return {"id": user.id, "username": user.username, "role": user.role, "message": "User created successfully"}


@router.post("/change-password")
def change_password(
    body: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Change the current user's password."""
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    current_user.hashed_password = get_password_hash(body.new_password)
    db.commit()
    _audit(db, "password_changed", current_user.username)
    return {"message": "Password changed successfully"}


@router.get("/users", response_model=list[UserProfileResponse])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    """List all users (admin only)."""
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [UserProfileResponse(
        id=u.id, username=u.username, email=u.email, full_name=u.full_name,
        role=u.role, agency=u.agency, badge_number=u.badge_number,
        is_active=u.is_active, created_at=u.created_at, last_login=u.last_login,
    ) for u in users]


@router.post("/seed-admin", status_code=201)
def seed_admin(db: Session = Depends(get_db)):
    """
    One-time setup: creates default admin account if no users exist.
    Only available when DEBUG=True. Remove or disable in production.
    """
    if not settings.DEBUG:
        raise HTTPException(
            status_code=403,
            detail="Seed endpoint is disabled in production. Set DEBUG=True to use it.",
        )

    if db.query(User).count() > 0:
        raise HTTPException(status_code=409, detail="Users already exist. Use /api/auth/users to create more.")

    default_password = "CyberForge@2026"
    admin = User(
        username="admin",
        email="admin@cyberforge.local",
        full_name="System Administrator",
        hashed_password=get_password_hash(default_password),
        role="admin",
        agency="CyberForge SOC",
    )
    db.add(admin)
    db.commit()
    logger.info("Default admin account created — change the password immediately.")
    return {
        "message": "Admin account created",
        "username": "admin",
        "warning": "Change this password immediately via /api/auth/change-password!",
    }
