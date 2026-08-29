from __future__ import annotations

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
    default_turnover_eur: float = 250_000_000.0
    acquisition_sweep_size: int = 10


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
