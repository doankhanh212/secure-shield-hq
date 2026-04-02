from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "HQG Web Security Platform"
    app_env: str = Field(default="production")
    app_debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")

    api_v1_prefix: str = "/api/v1"

    postgres_dsn: str = Field(
        default="postgresql+asyncpg://hqg:hqg@localhost:5432/hqg"
    )
    redis_url: str = Field(default="redis://localhost:6379/0")
    redis_result_backend: str = Field(default="redis://localhost:6379/1")

    elasticsearch_url: str = Field(default="http://localhost:9200")
    elasticsearch_username: str | None = Field(default=None)
    elasticsearch_password: str | None = Field(default=None)

    celery_task_default_queue: str = Field(default="queue_default")

    # CORS — comma-separated list of allowed origins
    allowed_origins: str = Field(default="http://localhost:3000,http://localhost:5173")

    # NVD API key — optional; without key rate limit is 5 req/30s
    nvd_api_key: str = Field(default="")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
