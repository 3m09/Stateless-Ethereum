import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates

import app.models  # noqa: F401
from app import __version__
from app.api import router as api_router
from app.artifacts import ArtifactStore
from app.config import Settings, get_settings
from app.database import Database
from app.ethereum.api import router as ethereum_api_router
from app.ethereum.rpc import default_rpc_factory
from app.ethereum.service import RPCFactory
from app.ethereum.views import router as ethereum_views_router
from app.migrations import upgrade_database
from app.trees.api import router as trees_api_router
from app.trees.views import router as trees_views_router
from app.views import router as views_router

APP_ROOT = Path(__file__).resolve().parent


def create_app(
    settings: Settings | None = None,
    ethereum_rpc_factory: RPCFactory = default_rpc_factory,
) -> FastAPI:
    application_settings = settings or get_settings()
    database = Database(application_settings.database_url)
    artifacts = ArtifactStore(application_settings.artifact_root)

    @asynccontextmanager
    async def lifespan(_application: FastAPI) -> AsyncIterator[None]:
        application_settings.prepare_runtime_directories()
        artifacts.bootstrap()
        if application_settings.auto_migrate:
            upgrade_database(application_settings)
        yield
        pending_tasks = list(_application.state.background_tasks)
        for task in pending_tasks:
            task.cancel()
        if pending_tasks:
            await asyncio.gather(*pending_tasks, return_exceptions=True)
        database.dispose()

    application = FastAPI(
        title=application_settings.app_name,
        version=__version__,
        debug=application_settings.debug,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    application.state.settings = application_settings
    application.state.database = database
    application.state.artifacts = artifacts
    application.state.templates = Jinja2Templates(directory=APP_ROOT / "templates")
    application.state.ethereum_rpc_factory = ethereum_rpc_factory
    application.state.background_tasks = set()

    static_assets = {
        path.name: path.read_bytes()
        for path in (APP_ROOT / "static").iterdir()
        if path.is_file()
    }
    media_types = {
        "styles.css": "text/css",
        "app.js": "application/javascript",
        "tree-viz.js": "application/javascript",
    }

    @application.get(
        "/static/{path}",
        name="static",
        include_in_schema=False,
    )
    async def static_asset(path: str) -> Response:
        content = static_assets.get(path)
        if content is None:
            raise HTTPException(status_code=404, detail="Static asset not found")
        return Response(
            content=content,
            media_type=media_types.get(path, "application/octet-stream"),
        )

    application.include_router(views_router)
    application.include_router(ethereum_views_router)
    application.include_router(trees_views_router)
    application.include_router(api_router)
    application.include_router(ethereum_api_router)
    application.include_router(trees_api_router)
    return application


app = create_app()


__all__ = ["app", "create_app"]
