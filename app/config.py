from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNTIME_ROOT = PROJECT_ROOT / "var"


class Settings(BaseSettings):
    """Application settings loaded from environment variables and `.env`."""

    app_name: str = "Stateless Ethereum Lab"
    environment: Literal["development", "test", "production"] = "development"
    debug: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)

    database_url: str = f"sqlite:///{DEFAULT_RUNTIME_ROOT / 'stateless_ethereum.db'}"
    artifact_root: Path = DEFAULT_RUNTIME_ROOT / "artifacts"
    auto_migrate: bool = True
    dashboard_job_limit: int = Field(default=25, ge=1, le=200)

    ethereum_rpc_url: str | None = None
    ethereum_network: str = "mainnet"
    ethereum_expected_chain_id: int = Field(default=1, ge=1)
    ethereum_request_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    ethereum_retry_attempts: int = Field(default=3, ge=1, le=10)
    ethereum_retry_backoff_seconds: float = Field(default=0.5, ge=0, le=30)
    ethereum_min_request_interval_seconds: float = Field(
        default=0.05,
        ge=0,
        le=10,
    )
    tree_setup_secret: SecretStr | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="STATELESS_",
        extra="ignore",
        case_sensitive=False,
    )

    @field_validator("artifact_root", mode="before")
    @classmethod
    def resolve_artifact_root(cls, value: str | Path) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        return path.resolve()

    @field_validator("tree_setup_secret", mode="before")
    @classmethod
    def validate_tree_setup_secret(
        cls,
        value: str | int | SecretStr | None,
    ) -> str | SecretStr | None:
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        raw_value = (
            value.get_secret_value()
            if isinstance(value, SecretStr)
            else str(value).strip()
        )
        if not raw_value.isdigit() or int(raw_value) < 1:
            raise ValueError("TREE_SETUP_SECRET must be a positive integer")
        return raw_value

    def require_tree_setup_secret(self) -> int:
        if self.tree_setup_secret is None:
            raise ValueError(
                "STATELESS_TREE_SETUP_SECRET is required for Verkle builds"
            )
        return int(self.tree_setup_secret.get_secret_value())

    @field_validator("database_url", mode="after")
    @classmethod
    def resolve_sqlite_database_url(cls, value: str) -> str:
        prefix = "sqlite:///"
        if not value.startswith(prefix):
            return value
        location = value.removeprefix(prefix)
        if location == ":memory:":
            return value
        path = Path(location).expanduser()
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        return f"{prefix}{path.resolve()}"

    def prepare_runtime_directories(self) -> None:
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        if self.database_url.startswith("sqlite:///"):
            database_path = Path(self.database_url.removeprefix("sqlite:///"))
            if not database_path.is_absolute():
                database_path = PROJECT_ROOT / database_path
            database_path.parent.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
