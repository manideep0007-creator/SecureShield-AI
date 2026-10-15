import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "SecureShield AI"
    ENVIRONMENT: str = "development"
    
    # API key for authenticating backend requests from authorized clients
    API_KEY: str | None = None

    # Base directory for SQLite databases and local data files
    DATA_DIR: str | None = None

    # These will be automatically populated from .env or environment variables
    # Production missing secrets will now raise a validation error at startup
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

settings = Settings()

