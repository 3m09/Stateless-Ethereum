import json
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.artifacts import ArtifactStore
from app.dependencies import get_artifact_store, get_database_session
from app.models import GeneratedTree, TreeStatus
from app.proofs.profiles import (
    PROOF_PROFILES,
    UnsupportedProofProfile,
    profiles_for_tree,
)
from app.proofs.schemas import ProofExperimentCreate
from app.proofs.service import (
    ProofExperimentNotFound,
    ProofExperimentService,
    ProofTreeNotFound,
    ProofTreeNotReady,
    TooManyProofKeys,
    create_experiment_records,
    schedule_proof_experiment,
)

router = APIRouter(include_in_schema=False)
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def proving_defaults() -> dict:
    defaults = {
        "tree_id": "",
        "prover_type": "merkle_optimized",
        "verifier_type": "merkle_optimized",
        "setup_type": "",
        "num_keys_to_prove": 1,
        "selection_seed": 0,
    }
    try:
        configured = json.loads(
            (PROJECT_ROOT / "proving_setup.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return defaults
    defaults.update(
        {
            "tree_id": str(configured.get("TREE_ID", "")),
            "prover_type": str(
                configured.get("PROVER_TYPE", defaults["prover_type"])
            ).lower(),
            "verifier_type": str(
                configured.get("VERIFIER_TYPE", defaults["verifier_type"])
            ).lower(),
            "setup_type": str(configured.get("SETUP_TYPE", "")).lower(),
            "num_keys_to_prove": min(
                max(int(configured.get("NUM_KEYS_TO_PROVE", 1)), 1),
                250,
            ),
        }
    )
    return defaults


def proof_page_context(
    session: Session,
    *,
    form_values: dict | None = None,
    errors: list[dict] | None = None,
) -> dict:
    statement = (
        select(GeneratedTree)
        .where(GeneratedTree.status == TreeStatus.READY)
        .order_by(GeneratedTree.created_at.desc())
    )
    trees = list(session.scalars(statement))
    tree_profiles = {
        tree.id: [profile.as_dict() for profile in profiles_for_tree(tree)]
        for tree in trees
    }
    return {
        "section": "proofs",
        "trees": trees,
        "tree_profiles": tree_profiles,
        "profiles": [profile.as_dict() for profile in PROOF_PROFILES],
        "experiments": ProofExperimentService(session).list(limit=50),
        "form_values": form_values or {},
        "proving_defaults": proving_defaults(),
        "errors": errors or [],
    }


@router.get("/proofs", response_class=HTMLResponse)
async def proofs_page(
    request: Request,
    session: Session = Depends(get_database_session),
) -> HTMLResponse:
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="proofs.html",
        context=proof_page_context(session),
    )


@router.post("/proofs/experiments")
async def create_proof_experiment_form(
    request: Request,
    name: str = Form(...),
    tree_id: str = Form(...),
    prover_type: str = Form(...),
    verifier_type: str = Form(...),
    setup_type: str = Form(""),
    num_keys_to_prove: str = Form("1"),
    selection_seed: str = Form("0"),
    session: Session = Depends(get_database_session),
    artifacts: ArtifactStore = Depends(get_artifact_store),
):
    form_values = {
        "name": name,
        "tree_id": tree_id,
        "prover_type": prover_type,
        "verifier_type": verifier_type,
        "setup_type": setup_type,
        "num_keys_to_prove": num_keys_to_prove,
        "selection_seed": selection_seed,
    }
    try:
        payload = ProofExperimentCreate(**form_values)
        if payload.setup_type == "verkle_kzg":
            request.app.state.settings.require_tree_setup_secret()
        experiment, _job = create_experiment_records(
            session=session,
            artifacts=artifacts,
            payload=payload,
        )
    except ValidationError as exc:
        errors = exc.errors(include_url=False)
    except ProofTreeNotFound:
        errors = [{"msg": "The selected tree does not exist"}]
    except (
        ProofTreeNotReady,
        TooManyProofKeys,
        UnsupportedProofProfile,
        ValueError,
    ) as exc:
        errors = [{"msg": str(exc)}]
    else:
        schedule_proof_experiment(request.app, experiment.id)
        return RedirectResponse(url=f"/proofs/{experiment.id}", status_code=303)

    return request.app.state.templates.TemplateResponse(
        request=request,
        name="proofs.html",
        context=proof_page_context(
            session,
            form_values=form_values,
            errors=errors,
        ),
        status_code=422,
    )


@router.get("/proofs/{experiment_id}", response_class=HTMLResponse)
async def proof_detail(
    experiment_id: str,
    request: Request,
    session: Session = Depends(get_database_session),
) -> HTMLResponse:
    try:
        experiment = ProofExperimentService(session).get(experiment_id)
    except ProofExperimentNotFound as exc:
        raise HTTPException(status_code=404, detail="Experiment not found") from exc
    tree = session.get(GeneratedTree, experiment.tree_id)
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="proof_detail.html",
        context={
            "section": "proofs",
            "experiment": experiment,
            "tree": tree,
        },
    )


@router.get(
    "/partials/proofs/{experiment_id}/summary",
    response_class=HTMLResponse,
)
async def proof_summary_partial(
    experiment_id: str,
    request: Request,
    session: Session = Depends(get_database_session),
) -> HTMLResponse:
    try:
        experiment = ProofExperimentService(session).get(experiment_id)
    except ProofExperimentNotFound as exc:
        raise HTTPException(status_code=404, detail="Experiment not found") from exc
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="partials/proof_summary.html",
        context={"experiment": experiment},
    )
