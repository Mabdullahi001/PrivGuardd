from __future__ import annotations
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyUrl, Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "PrivGuard"
    ENV: str = "dev"
    BASE_URL: str = "http://localhost:8000"
    FRONTEND_URL: str = "http://localhost:5173"

    JWT_SECRET: str = Field(default="change_me")
    JWT_EXPIRES_MINUTES: int = 60
    TOKEN_ENC_KEY: str = Field(default="")  # Fernet key

    DATABASE_URL: str = "postgresql+psycopg2://privguard:privguard@localhost:5432/privguard"

    GOOGLE_CLIENT_SECRETS_FILE: str = "./credentials/google_client_secret.json"
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/gmail/oauth/callback"
    GOOGLE_SCOPES: str = "https://www.googleapis.com/auth/gmail.readonly"

settings = Settings()
