from collections.abc import AsyncGenerator

import httpx2
import pytest

from app.config import Settings
from app.main import create_app


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def client(tmp_path) -> AsyncGenerator[httpx2.AsyncClient, None]:
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        artifact_root=tmp_path / "artifacts",
        auto_migrate=True,
        tree_setup_secret="123456789",
    )
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        transport = httpx2.ASGITransport(app=application)
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as test_client:
            test_client.application = application
            yield test_client
