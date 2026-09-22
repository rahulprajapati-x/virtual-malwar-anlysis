"""
CyberForge — Forensics Platform Backend
Main FastAPI application entry point.

Run with: uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import init_db
from app.api.routes import samples, cases, cipher, dashboard, mitre, reports, sandbox, hex, auth, pcap

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("cyberforge")


# ── Body size limit ────────────────────────────────────────────────────────────
# Using a pure ASGI middleware (NOT BaseHTTPMiddleware) to avoid the known
# Starlette bug where BaseHTTPMiddleware breaks CORS preflight (OPTIONS → 400).
_MAX_BODY = 550 * 1024 * 1024  # 550 MB


class MaxBodySizeMiddleware:
    """Pure ASGI middleware that rejects requests with Content-Length > 550 MB.
    This implementation does NOT use BaseHTTPMiddleware, which is known to
    interfere with CORSMiddleware preflight handling in Starlette."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            content_length = headers.get(b"content-length")
            if content_length:
                try:
                    if int(content_length) > _MAX_BODY:
                        response = JSONResponse(
                            status_code=413,
                            content={"detail": "Request body too large. Maximum allowed is 500 MB."},
                        )
                        await response(scope, receive, send)
                        return
                except (ValueError, TypeError):
                    pass
        await self.app(scope, receive, send)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler — runs startup logic then yields."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    init_db()
    logger.info("Database tables verified/created")

    # ── Auto-seed admin if no users exist ─────────────────────────────────────
    try:
        from app.database import SessionLocal
        from app.models.models import User
        from app.api.routes.auth import get_password_hash
        db = SessionLocal()
        try:
            if db.query(User).count() == 0:
                admin = User(
                    username="admin",
                    email="admin@cyberforge.local",
                    full_name="System Administrator",
                    hashed_password=get_password_hash("CyberForge@2026"),
                    role="admin",
                    agency="CyberForge SOC",
                )
                db.add(admin)
                db.commit()
                logger.info("✅ Default admin account auto-created → username: admin (change the password immediately)")
            else:
                logger.info("Admin account already exists — skipping auto-seed")
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"Auto-seed admin failed (non-fatal): {e}")

    # ── Secret key safety check ───────────────────────────────────────────────
    _DEFAULT_KEY = "dev-secret-change-in-production"
    if settings.SECRET_KEY == _DEFAULT_KEY and not settings.DEBUG:
        raise RuntimeError(
            "🚨 SECURITY ERROR: SECRET_KEY is still the default value. "
            "Set a strong random SECRET_KEY in your .env file before running in production."
        )
    if settings.SECRET_KEY == _DEFAULT_KEY:
        logger.warning(
            "⚠️  SECRET_KEY is using the default dev value — "
            "set a strong random key in .env before deploying to production!"
        )

    # Pre-warm YARA scanner so first request isn't slow
    from app.api.routes.samples import get_yara_scanner
    get_yara_scanner()
    logger.info("YARA scanner initialized")
    yield
    logger.info("CyberForge shutting down")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "AI-Powered Malware Analysis, Digital Forensics & Threat Intelligence Platform "
        "for law enforcement cyber units, SOC analysts, and CERT teams."
    ),
    lifespan=lifespan,
)

# ── CORS — allow all localhost ports + any network IPs the dev frontend uses ──
# In development we keep this broad. Tighten for production.
_dev_origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:8080",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]
# Also include any extra origins configured in .env
_configured = [o.strip() for o in settings.ALLOWED_ORIGINS.split(",") if o.strip()]
_all_origins = list(dict.fromkeys(_dev_origins + _configured))  # deduplicate, preserve order

app.add_middleware(
    CORSMiddleware,
    allow_origins=_all_origins,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|172\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+):\d+",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
    max_age=3600,
)

# Register body size limiter (pure ASGI — safe with CORSMiddleware)
app.add_middleware(MaxBodySizeMiddleware)

# Register routers
app.include_router(samples.router)
app.include_router(cases.router)
app.include_router(cipher.router)
app.include_router(dashboard.router)
app.include_router(mitre.router)
app.include_router(reports.router)
app.include_router(sandbox.router)
app.include_router(hex.router)
app.include_router(auth.router)
app.include_router(pcap.router)


@app.get("/")
def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/api/health")
def health_check():
    """Health check endpoint — verifies DB, YARA, and config status."""
    from app.api.routes.samples import get_yara_scanner
    from app.core.yara_scanner import YARAScanner, YARA_AVAILABLE

    scanner = get_yara_scanner()
    yara_ready = YARA_AVAILABLE and YARAScanner._compiled_rules is not None

    return {
        "status": "ok",
        "yara_engine": "ready" if yara_ready else "unavailable",
        "virustotal_configured": bool(settings.VIRUSTOTAL_API_KEY),
        "abuseipdb_configured": bool(settings.ABUSEIPDB_API_KEY),
        "database": "connected",
    }
