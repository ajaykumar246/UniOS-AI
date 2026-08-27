from pydantic import ConfigDict
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SUPABASE_URL: str = "https://placeholder-project.supabase.co"
    SUPABASE_ANON_KEY: str = "placeholder-anon-key"
    SUPABASE_SERVICE_KEY: str = "placeholder-service-key"
    SUPABASE_JWT_SECRET: str = "placeholder-jwt-secret-at-least-32-chars-long-placeholder"
    FRONTEND_URL: str = "http://localhost:3000"
    ALLOWED_REDIRECT_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000"
    ]

    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
