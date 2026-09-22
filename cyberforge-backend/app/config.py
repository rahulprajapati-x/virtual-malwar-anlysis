"""
CyberForge — Application Configuration
Reads from .env file or environment variables
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
    )

    # App
    APP_NAME: str = "CyberForge Forensics Platform"
    APP_VERSION: str = "3.0.0"
    DEBUG: bool = False
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:5173"

    # Database
    DATABASE_URL: str = "postgresql://cyberforge:password@localhost:5432/cyberforge_db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # File storage
    UPLOAD_DIR: str = "./uploads"
    MAX_FILE_SIZE_MB: int = 500
    YARA_RULES_DIR: str = "./yara_rules"

    # Threat Intelligence APIs
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""
    MALWAREBAZAAR_API_KEY: str = ""

    # Sandbox
    ANYRUN_API_KEY: str = ""

    # JWT
    SECRET_KEY: str = "dev-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 480

    @property
    def origins_list(self):
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",")]

    @property
    def upload_path(self) -> Path:
        p = Path(self.UPLOAD_DIR)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def yara_rules_path(self) -> Path:
        return Path(self.YARA_RULES_DIR)

    @property
    def max_file_bytes(self) -> int:
        return self.MAX_FILE_SIZE_MB * 1024 * 1024


settings = Settings()
