import json
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.artifacts import ArtifactStore
from app.dependencies import get_artifact_store, get_database_session
from app.limits import MAX_EXPERIMENT_KEYS
from app.models import DatasetStatus, EthereumDataset, TreeType
from app.trees.schemas import TreeBuildCreate
from app.trees.service import (
    DatasetNotReady,
    GeneratedTreeService,
    InsufficientDatasetKeys,
    TreeDatasetNotFound,
    TreeNotFound,
    create_tree_records,
    schedule_tree_build,
)

router = APIRouter(include_in_schema=False)
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def tree_generation_defaults() -> dict:
    defaults = {
        "tree_type": "merkle_patricia",
        "hash_function": "keccak",
        "setup_type": "",
        "key_length": 32,
        "width": 16,
        "key_count": 25,
        "insertion_order": "secure_key",
    }
    path = PROJECT_ROOT / "tree_generation_setup.json"
    try:
        configured = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return defaults

    configured_type = str(configured.get("TREE_TYPE", "")).lower()
    configured_hash = str(configured.get("HASH_FN", "")).lower()
    if configured_type == "verkle":
        defaults["tree_type"] = "verkle"
        defaults["hash_function"] = "kzg"
    elif configured_type == "poseidon_merkle" or configured_hash == "poseidon":
        defaults["tree_type"] = "poseidon_merkle"
        defaults["hash_function"] = "poseidon"

    defaults.update(
        {
            "setup_type": str(configured.get("SETUP_TYPE", "")),
            "key_length": configured.get("KEY_LENGTH", 32),
            "width": configured.get("WIDTH", 16),
            "key_count": min(
                int(configured.get("NUM_KEYS", 25)),
                MAX_EXPERIMENT_KEYS,
            ),
        }
    )
    if defaults["tree_type"] == "verkle":
        defaults["setup_type"] = defaults["setup_type"] or "verkle_kzg"
    else:
        defaults["setup_type"] = ""
    return defaults


def tree_page_context(
    session: Session,
    *,
    form_values: dict | None = None,
    errors: list[dict] | None = None,
) -> dict:
    dataset_statement = (
        select(EthereumDataset)
        .where(EthereumDataset.status == DatasetStatus.READY)
        .order_by(EthereumDataset.created_at.desc())
    )
    return {
        "section": "trees",
        "datasets": list(session.scalars(dataset_statement)),
        "trees": GeneratedTreeService(session).list(limit=50),
        "form_values": form_values or {},
        "generation_defaults": tree_generation_defaults(),
        "errors": errors or [],
    }


@router.get("/trees", response_class=HTMLResponse)
async def trees_page(
    request: Request,
    session: Session = Depends(get_database_session),
) -> HTMLResponse:
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="trees.html",
        context=tree_page_context(session),
    )


@router.post("/trees/builds")
async def create_tree_build_form(
    request: Request,
    name: str = Form(...),
    dataset_id: str = Form(...),
    tree_type: str = Form("merkle_patricia"),
    hash_function: str = Form("keccak"),
    setup_type: str = Form(""),
    key_length: str = Form("32"),
    width: str = Form("16"),
    key_count: str = Form(""),
    insertion_order: str = Form("secure_key"),
    session: Session = Depends(get_database_session),
    artifacts: ArtifactStore = Depends(get_artifact_store),
):
    form_values = {
        "name": name,
        "dataset_id": dataset_id,
        "tree_type": tree_type,
        "hash_function": hash_function,
        "setup_type": setup_type,
        "key_length": key_length,
        "width": width,
        "key_count": key_count,
        "insertion_order": insertion_order,
    }
    try:
        payload = TreeBuildCreate(
            name=name,
            dataset_id=dataset_id,
            tree_type=tree_type,
            hash_function=hash_function,
            setup_type=setup_type,
            key_length=key_length,
            width=width,
            key_count=key_count if key_count.strip() else None,
            insertion_order=insertion_order,
        )
        if payload.tree_type == TreeType.VERKLE:
            request.app.state.settings.require_tree_setup_secret()
        tree, _job = create_tree_records(
            session=session,
            artifacts=artifacts,
            payload=payload,
        )
    except ValidationError as exc:
        errors = exc.errors(include_url=False)
    except TreeDatasetNotFound:
        errors = [{"msg": "The selected dataset does not exist"}]
    except (DatasetNotReady, InsufficientDatasetKeys) as exc:
        errors = [{"msg": str(exc)}]
    except ValueError as exc:
        errors = [{"msg": str(exc)}]
    else:
        schedule_tree_build(request.app, tree.id)
        return RedirectResponse(url=f"/trees/{tree.id}", status_code=303)

    return request.app.state.templates.TemplateResponse(
        request=request,
        name="trees.html",
        context=tree_page_context(
            session,
            form_values=form_values,
            errors=errors,
        ),
        status_code=422,
    )


@router.get("/trees/{tree_id}", response_class=HTMLResponse)
async def tree_detail(
    tree_id: str,
    request: Request,
    session: Session = Depends(get_database_session),
) -> HTMLResponse:
    try:
        tree = GeneratedTreeService(session).get(tree_id)
    except TreeNotFound as exc:
        raise HTTPException(status_code=404, detail="Tree not found") from exc
    dataset = session.get(EthereumDataset, tree.dataset_id)
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tree_detail.html",
        context={
            "section": "trees",
            "tree": tree,
            "dataset": dataset,
        },
    )


@router.get("/partials/trees/{tree_id}/summary", response_class=HTMLResponse)
async def tree_summary_partial(
    tree_id: str,
    request: Request,
    session: Session = Depends(get_database_session),
) -> HTMLResponse:
    try:
        tree = GeneratedTreeService(session).get(tree_id)
    except TreeNotFound as exc:
        raise HTTPException(status_code=404, detail="Tree not found") from exc
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="partials/tree_summary.html",
        context={"tree": tree},
    )
