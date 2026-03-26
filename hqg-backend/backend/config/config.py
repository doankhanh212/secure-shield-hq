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
    app_env: str = Field(default="development")
    app_debug: bool = Field(default=True)
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

    # NVD API key — tùy chọn, không bắt buộc
    # Không có key: rate limit 5 req/30s; có key: 50 req/30s
    # Đăng ký miễn phí: https://nvd.nist.gov/developers/request-an-api-key
    nvd_api_key: str = Field(default="")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
