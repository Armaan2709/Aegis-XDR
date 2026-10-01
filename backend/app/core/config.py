"""
AegisAI XDR Configuration Manager.

Provides typed, validated configuration parameters sourced from environment variables,
supporting local development, automated testing, and hardened production deployments.
"""

import json
from typing import List, Union
from pydantic import AnyHttpUrl, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Platform global application settings."""

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.development", "../.env", "../.env.development"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    # Core System Identification
    APP_NAME: str = "AegisAI XDR"
    APP_ENV: str = "development"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "dev_super_secret_key_change_me_in_prod_512bits"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Network Boundary & Security
    HOST: str = "0.0.0.0"
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    # SOAR Execution Constraint
    SOAR_EXECUTION_MODE: str = "SAFE_MOCK_EXECUTION"

    @field_validator("CORS_ORIGINS", mode="before")
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        raise ValueError(v)

    @field_validator("SOAR_EXECUTION_MODE")
    def validate_soar_execution_mode(cls, v: str) -> str:
        allowed = "SAFE_MOCK_EXECUTION"
        if v != allowed:
            raise ValueError(f"Invalid SOAR_EXECUTION_MODE: must be {allowed}")
        return v

    # PostgreSQL Relational Engine Settings
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "aegis_user"
    POSTGRES_PASSWORD: str = "aegis_secure_password"
    POSTGRES_DB: str = "aegis_xdr_db"
    DATABASE_URL: str = (
        "postgresql+asyncpg://aegis_user:aegis_secure_password@localhost:5432/aegis_xdr_db"
    )

    # Redis Cache & Pub/Sub Settings
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""
    REDIS_URL: str = "redis://localhost:6379/0"

    # Elasticsearch Telemetry Search Settings
    ELASTICSEARCH_HOST: str = "localhost"
    ELASTICSEARCH_PORT: int = 9200
    ELASTICSEARCH_URL: str = "http://localhost:9200"
    ELASTICSEARCH_USERNAME: str = ""
    ELASTICSEARCH_PASSWORD: str = ""

    # AI Model & Local LLM Settings
    LLM_PROVIDER: str = "ollama"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    DEFAULT_LLM_MODEL: str = "llama3:8b"
    EMBEDDING_MODEL: str = "all-minilm:l6-v2"

    # Observability & Security Constraints
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    RATE_LIMIT_PER_MINUTE: int = 100

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        env = (self.ENVIRONMENT or self.APP_ENV or "development").lower()
        if env in ["production", "prod"]:
            # Check SECRET_KEY entropy and defaults
            insecure_keys = [
                "dev_super_secret_key_change_me_in_prod_512bits",
                "secret",
                "change_me",
                "password",
                "12345678",
            ]
            if self.SECRET_KEY in insecure_keys or len(self.SECRET_KEY) < 32:
                raise ValueError(
                    "Production deployment error: SECRET_KEY must be securely configured with at least 32 characters."
                )

            # Check CORS wildcard
            if "*" in self.CORS_ORIGINS:
                raise ValueError(
                    "Production deployment error: CORS_ORIGINS cannot contain wildcard '*'"
                )

            # Check JWT Expiration
            if self.ACCESS_TOKEN_EXPIRE_MINUTES <= 0:
                raise ValueError(
                    "Production deployment error: ACCESS_TOKEN_EXPIRE_MINUTES must be positive."
                )

        return self


# Global Singleton Settings Instance
settings = Settings()

