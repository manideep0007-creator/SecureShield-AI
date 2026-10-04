from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "SecureShield AI"
    ENVIRONMENT: str = "development"
    
    # These will be automatically populated from .env or environment variables
    # Production missing secrets will now raise a validation error at startup
    GOOGLE_SAFE_BROWSING_API_KEY: str | None = None
    VIRUSTOTAL_API_KEY: str | None = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()

