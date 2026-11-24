import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "SecureShield AI"
    ENVIRONMENT: str = "development"
    
    # API key for authenticating backend requests from authorized clients
    # In production, default dev key must be overridden via environment variable
    API_KEY: str | None = "secureshield_dev_secret_key_2026"

    # Base directory for SQLite databases and local data files
    DATA_DIR: str | None = None

    # Google OAuth2 Client ID for token audience validation
    # Default provided for local development and test fixtures; strictly enforced in production
    GOOGLE_CLIENT_ID: str | None = "expected-client-id.apps.googleusercontent.com"

    # Distributed Rate Limiting (Redis URL, or SQLite shared database if not set)
    REDIS_URL: str | None = None

    # Trusted proxy IPs or CIDRs allowed to supply X-Forwarded-For headers
    TRUSTED_PROXIES: str = "127.0.0.1,::1,testclient,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

    # Threat Intelligence external API keys
    GOOGLE_SAFE_BROWSING_API_KEY: str | None = None
    VIRUSTOTAL_API_KEY: str | None = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def resolved_data_dir(self) -> str:
        env_data_dir = os.getenv("DATA_DIR")
        if env_data_dir:
            return os.path.abspath(env_data_dir)
        if self.DATA_DIR:
            return os.path.abspath(self.DATA_DIR)
        return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))

    @property
    def trusted_proxy_list(self) -> list[str]:
        return [p.strip() for p in self.TRUSTED_PROXIES.split(",") if p.strip()]

    def validate_production_configuration(self) -> None:
        """Enforces that production builds have non-default secrets configured."""
        if self.ENVIRONMENT == "production":
            if not self.API_KEY or self.API_KEY == "secureshield_dev_secret_key_2026":
                raise ValueError(
                    "Production security violation: API_KEY must be explicitly set and cannot "
                    "use the default development secret."
                )
            if (
                not self.GOOGLE_CLIENT_ID
                or not self.GOOGLE_CLIENT_ID.strip()
                or self.GOOGLE_CLIENT_ID == "expected-client-id.apps.googleusercontent.com"
            ):
                raise ValueError(
                    "Production security violation: GOOGLE_CLIENT_ID must be explicitly configured in production "
                    "and cannot use test/development defaults."
                )

settings = Settings()
