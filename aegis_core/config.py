from __future__ import annotations

import os
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", extra="ignore")

    environment: str = "development"
    api_title: str = "Aegis Governance Engine"
    api_version: str = "0.1.0"
    loop_interval_seconds: float = 2.0
    ingest_batch_size: int = 8
    high_risk_threshold: float = 70.0
    critical_risk_threshold: float = 90.0
    default_reviewers: tuple[str, ...] = ("security-approvers", "compliance-legal")
    default_base_branch: str = "main"
    signing_key: str = "dev-rotate-aegis-hmac-signing-key"
    api_key: str = "dev-aegis-api-key"
    default_turnover_eur: float = 250_000_000.0
    acquisition_sweep_size: int = 10


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def listen_host() -> str:
    """Bind address. Railway (and any PORT-based PaaS) must use 0.0.0.0, not 127.0.0.1."""
    explicit = os.environ.get("HOST") or os.environ.get("AEGIS_HOST")
    if explicit:
        return explicit
    if os.environ.get("PORT") or os.environ.get("RAILWAY_ENVIRONMENT"):
        return "0.0.0.0"
    return "127.0.0.1"


def listen_port() -> int:
    """Railway injects PORT; fall back to 8080 for local runs."""
    raw = os.environ.get("PORT") or os.environ.get("AEGIS_PORT") or "8080"
    return int(raw)
