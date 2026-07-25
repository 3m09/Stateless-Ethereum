from collections.abc import AsyncGenerator

from fastapi import Request
from sqlalchemy.orm import Session

from app.artifacts import ArtifactStore


async def get_database_session(
    request: Request,
) -> AsyncGenerator[Session, None]:
    with request.app.state.database.session() as session:
        yield session


async def get_artifact_store(request: Request) -> ArtifactStore:
    return request.app.state.artifacts
