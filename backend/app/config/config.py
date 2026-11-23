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

    def validate_production_configuration(self) -> None:
        """Enforces that production builds have non-default secrets configured."""
        if self.ENVIRONMENT == "production":
            if not self.API_KEY or self.API_KEY == "secureshield_dev_secret_key_2026":
                raise ValueError(
                    "Production security violation: API_KEY must be explicitly set and cannot "
                    "use the default development secret."
                )

settings = Settings()
