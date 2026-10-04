from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    jwt_secret: str = Field(min_length=32)
    jwt_expire_minutes: int = 30
    cors_origins: str = "http://localhost:5173"
    oidc_issuer_url: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_redirect_uri: str | None = None
    frontend_url: str = "http://localhost:5173"
    allow_public_signup: bool = False
    password_reset_dev_mode: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None
    smtp_starttls: bool = True
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
