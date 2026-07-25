from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from app.models import JobKind, JobStatus


def redact_secrets(value: Any) -> Any:
    """Return a presentation-safe copy of nested job/configuration data."""

    if isinstance(value, dict):
        return {
            key: (
                "[redacted]"
                if key.lower() == "secret"
                else redact_secrets(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value


class JobCreate(BaseModel):
    kind: JobKind
    parameters: dict[str, Any] = Field(default_factory=dict)
    message: str | None = Field(default=None, max_length=500)


class JobUpdate(BaseModel):
    status: JobStatus
    progress: int | None = Field(default=None, ge=0, le=100)
    message: str | None = Field(default=None, max_length=500)
    result: dict[str, Any] | None = None
    error: str | None = None


class JobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: JobKind
    status: JobStatus
    progress: int
    message: str | None
    parameters: dict[str, Any]
    result: dict[str, Any] | None
    error: str | None
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    finished_at: datetime | None

    @field_serializer("parameters")
    def serialize_parameters(self, value: dict[str, Any]) -> dict[str, Any]:
        return redact_secrets(value)


class HealthRead(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    database: Literal["ok", "error"]
    artifact_store: Literal["ok", "error"]
