"""FastAPI application configuration using Pydantic."""
from typing import List
from pydantic_settings import BaseSettings
import os


class Settings(BaseSettings):
    """
    Application settings with environment variable support.
    
    All values can be overridden with environment variables.
    Use .env file for local development.
    """
    
    # Application
    APP_NAME: str = "Secure Auth Lab"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://secure_user:secure_password@localhost:5432/secure_auth_db"
    )
    SQLALCHEMY_ECHO: bool = os.getenv("SQLALCHEMY_ECHO", "false").lower() == "true"
    
    # Redis
    REDIS_URL: str = os.getenv(
        "REDIS_URL",
        "redis://localhost:6379/0"
    )
    
    # Security
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "your-super-secret-key-change-in-production-min-32-chars-!!!"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    
    # Password Security
    PASSWORD_MIN_LENGTH: int = int(os.getenv("PASSWORD_MIN_LENGTH", "12"))
    PASSWORD_REQUIRE_UPPERCASE: bool = os.getenv("PASSWORD_REQUIRE_UPPERCASE", "true").lower() == "true"
    PASSWORD_REQUIRE_LOWERCASE: bool = os.getenv("PASSWORD_REQUIRE_LOWERCASE", "true").lower() == "true"
    PASSWORD_REQUIRE_DIGITS: bool = os.getenv("PASSWORD_REQUIRE_DIGITS", "true").lower() == "true"
    PASSWORD_REQUIRE_SPECIAL: bool = os.getenv("PASSWORD_REQUIRE_SPECIAL", "true").lower() == "true"
    
    # CORS
    ALLOWED_ORIGINS: str = os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://localhost:8000"
    )
    ALLOW_CREDENTIALS: bool = os.getenv("ALLOW_CREDENTIALS", "true").lower() == "true"
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
    BRUTE_FORCE_MAX_ATTEMPTS: int = int(os.getenv("BRUTE_FORCE_MAX_ATTEMPTS", "5"))
    BRUTE_FORCE_LOCKOUT_MINUTES: int = int(os.getenv("BRUTE_FORCE_LOCKOUT_MINUTES", "15"))
    
    # 2FA/TOTP
    TOTP_ISSUER: str = os.getenv("TOTP_ISSUER", "SecureAuthLab")
    TOTP_WINDOW: int = int(os.getenv("TOTP_WINDOW", "1"))
    
    # Elasticsearch
    ELASTICSEARCH_URL: str = os.getenv(
        "ELASTICSEARCH_URL",
        "http://localhost:9200"
    )
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Global settings instance
_settings: Settings = None


def get_settings() -> Settings:
    """
    Get application settings.
    
    Implements singleton pattern to ensure single instance.
    
    Returns:
        Settings instance
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
