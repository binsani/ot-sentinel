from functools import lru_cache
from typing import Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "OT-Sentinel API"
    database_url: str = Field(
        default="postgresql+psycopg://ot_sentinel:ot_sentinel@localhost:5432/ot_sentinel"
    )
    sensor_ingest_api_key: SecretStr = Field(default=SecretStr("development-only-key"))
    viewer_api_key: SecretStr = Field(default=SecretStr("development-viewer-key"))
    admin_api_key: SecretStr = Field(default=SecretStr("development-admin-key"))
    bootstrap_api_keys_enabled: bool = False
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_jwks_file: str | None = None
    webhook_signing_secret: SecretStr | None = None

    @model_validator(mode="after")
    def validate_authentication_configuration(self) -> Self:
        if self.bootstrap_api_keys_enabled:
            keys = [
                self.viewer_api_key.get_secret_value(),
                self.admin_api_key.get_secret_value(),
            ]
            if any(len(key) < 24 for key in keys) or len(set(keys)) != len(keys):
                raise ValueError("bootstrap API keys must be distinct and at least 24 characters")
        oidc_values = [
            self.oidc_issuer,
            self.oidc_audience,
            self.oidc_jwks_url,
            self.oidc_jwks_file,
        ]
        if any(oidc_values):
            if not self.oidc_issuer or not self.oidc_audience:
                raise ValueError("OIDC issuer and audience are required")
            if bool(self.oidc_jwks_url) == bool(self.oidc_jwks_file):
                raise ValueError("configure exactly one OIDC JWKS source")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
