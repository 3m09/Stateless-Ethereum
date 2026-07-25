from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.artifacts import ArtifactStore
from app.dependencies import get_artifact_store, get_database_session
from app.models import TreeType
from app.trees.schemas import (
    GeneratedTreeRead,
    TreeBuildAccepted,
    TreeBuildCreate,
    TreeVisualization,
)
from app.trees.service import (
    DatasetNotReady,
    GeneratedTreeService,
    InsufficientDatasetKeys,
    TreeDatasetNotFound,
    TreeNotFound,
    create_tree_records,
    schedule_tree_build,
)

router = APIRouter(prefix="/api/v1/trees", tags=["trees"])


@router.post("/builds", response_model=TreeBuildAccepted, status_code=202)
async def create_tree_build(
    payload: TreeBuildCreate,
    request: Request,
    session: Session = Depends(get_database_session),
    artifacts: ArtifactStore = Depends(get_artifact_store),
) -> TreeBuildAccepted:
    if payload.tree_type == TreeType.VERKLE:
        try:
            request.app.state.settings.require_tree_setup_secret()
        except ValueError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    try:
        tree, job = create_tree_records(
            session=session,
            artifacts=artifacts,
            payload=payload,
        )
    except TreeDatasetNotFound as exc:
        raise HTTPException(status_code=404, detail="Dataset not found") from exc
    except (DatasetNotReady, InsufficientDatasetKeys) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    schedule_tree_build(request.app, tree.id)
    return TreeBuildAccepted(tree=tree, job=job)


@router.get("", response_model=list[GeneratedTreeRead])
async def list_trees(
    limit: int = Query(default=50, ge=1, le=200),
    session: Session = Depends(get_database_session),
) -> list[GeneratedTreeRead]:
    trees = GeneratedTreeService(session).list(limit=limit)
    return [GeneratedTreeRead.model_validate(tree) for tree in trees]


@router.get("/{tree_id}", response_model=GeneratedTreeRead)
async def get_tree(
    tree_id: str,
    session: Session = Depends(get_database_session),
) -> GeneratedTreeRead:
    try:
        tree = GeneratedTreeService(session).get(tree_id)
    except TreeNotFound as exc:
        raise HTTPException(status_code=404, detail="Tree not found") from exc
    return GeneratedTreeRead.model_validate(tree)


@router.get(
    "/{tree_id}/visualization",
    response_model=TreeVisualization,
)
async def get_tree_visualization(
    tree_id: str,
    session: Session = Depends(get_database_session),
    artifacts: ArtifactStore = Depends(get_artifact_store),
) -> TreeVisualization:
    try:
        tree = GeneratedTreeService(session).get(tree_id)
    except TreeNotFound as exc:
        raise HTTPException(status_code=404, detail="Tree not found") from exc
    if not tree.artifact_path:
        raise HTTPException(status_code=409, detail="Tree visualization is not ready")
    path = artifacts.path_for("trees", tree.id) / "visualization.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Visualization artifact not found")
    return TreeVisualization.model_validate(artifacts.read_json(path))
