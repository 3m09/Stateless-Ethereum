from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.artifacts import ArtifactStore
from app.dependencies import get_artifact_store, get_database_session
from app.proofs.profiles import PROOF_PROFILES, UnsupportedProofProfile
from app.proofs.schemas import (
    ProofExperimentAccepted,
    ProofExperimentCreate,
    ProofExperimentRead,
    ProofProfileRead,
)
from app.proofs.service import (
    ProofExperimentNotFound,
    ProofExperimentService,
    ProofTreeNotFound,
    ProofTreeNotReady,
    TooManyProofKeys,
    create_experiment_records,
    schedule_proof_experiment,
)

router = APIRouter(prefix="/api/v1/proofs", tags=["proofs"])


@router.get("/profiles", response_model=list[ProofProfileRead])
async def list_proof_profiles() -> list[ProofProfileRead]:
    return [
        ProofProfileRead.model_validate(profile.as_dict()) for profile in PROOF_PROFILES
    ]


@router.post(
    "/experiments",
    response_model=ProofExperimentAccepted,
    status_code=202,
)
async def create_proof_experiment(
    payload: ProofExperimentCreate,
    request: Request,
    session: Session = Depends(get_database_session),
    artifacts: ArtifactStore = Depends(get_artifact_store),
) -> ProofExperimentAccepted:
    if payload.setup_type == "verkle_kzg":
        try:
            request.app.state.settings.require_tree_setup_secret()
        except ValueError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    try:
        experiment, job = create_experiment_records(
            session=session,
            artifacts=artifacts,
            payload=payload,
        )
    except ProofTreeNotFound as exc:
        raise HTTPException(status_code=404, detail="Tree not found") from exc
    except (ProofTreeNotReady, TooManyProofKeys, UnsupportedProofProfile) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    schedule_proof_experiment(request.app, experiment.id)
    return ProofExperimentAccepted(experiment=experiment, job=job)


@router.get("/experiments", response_model=list[ProofExperimentRead])
async def list_proof_experiments(
    limit: int = Query(default=50, ge=1, le=200),
    session: Session = Depends(get_database_session),
) -> list[ProofExperimentRead]:
    experiments = ProofExperimentService(session).list(limit=limit)
    return [ProofExperimentRead.model_validate(item) for item in experiments]


@router.get("/experiments/{experiment_id}", response_model=ProofExperimentRead)
async def get_proof_experiment(
    experiment_id: str,
    session: Session = Depends(get_database_session),
) -> ProofExperimentRead:
    try:
        experiment = ProofExperimentService(session).get(experiment_id)
    except ProofExperimentNotFound as exc:
        raise HTTPException(status_code=404, detail="Experiment not found") from exc
    return ProofExperimentRead.model_validate(experiment)
