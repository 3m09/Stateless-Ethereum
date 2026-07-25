from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from app import __version__
from app.artifacts import ArtifactStore
from app.dependencies import get_artifact_store, get_database_session
from app.models import JobStatus
from app.schemas import HealthRead, JobCreate, JobRead, JobUpdate
from app.services.jobs import InvalidJobTransition, JobNotFound, JobService

router = APIRouter()


@router.get("/healthz", response_model=HealthRead, tags=["system"])
async def health(request: Request, response: Response) -> HealthRead:
    database_status = "ok"
    artifact_status = "ok"

    try:
        request.app.state.database.ping()
    except Exception:
        database_status = "error"

    try:
        root = request.app.state.artifacts.root
        if not root.is_dir():
            artifact_status = "error"
    except Exception:
        artifact_status = "error"

    overall_status = (
        "ok" if database_status == "ok" and artifact_status == "ok" else "degraded"
    )
    if overall_status == "degraded":
        response.status_code = 503

    return HealthRead(
        status=overall_status,
        version=__version__,
        database=database_status,
        artifact_store=artifact_status,
    )


@router.post(
    "/api/v1/jobs",
    response_model=JobRead,
    status_code=201,
    tags=["jobs"],
)
async def create_job(
    payload: JobCreate,
    session: Session = Depends(get_database_session),
    artifacts: ArtifactStore = Depends(get_artifact_store),
) -> JobRead:
    job = JobService(session).create(payload)
    artifacts.initialize_job(
        job.id,
        {
            "job_id": job.id,
            "kind": job.kind.value,
            "status": job.status.value,
            "parameters": job.parameters,
            "created_at": job.created_at,
        },
    )
    return JobRead.model_validate(job)


@router.get("/api/v1/jobs", response_model=list[JobRead], tags=["jobs"])
async def list_jobs(
    status: JobStatus | None = None,
    limit: int = Query(default=25, ge=1, le=200),
    session: Session = Depends(get_database_session),
) -> list[JobRead]:
    jobs = JobService(session).list(status=status, limit=limit)
    return [JobRead.model_validate(job) for job in jobs]


@router.get("/api/v1/jobs/{job_id}", response_model=JobRead, tags=["jobs"])
async def get_job(
    job_id: str,
    session: Session = Depends(get_database_session),
) -> JobRead:
    try:
        job = JobService(session).get(job_id)
    except JobNotFound as exc:
        raise HTTPException(status_code=404, detail="Job not found") from exc
    return JobRead.model_validate(job)


@router.patch("/api/v1/jobs/{job_id}", response_model=JobRead, tags=["jobs"])
async def update_job(
    job_id: str,
    payload: JobUpdate,
    session: Session = Depends(get_database_session),
) -> JobRead:
    try:
        job = JobService(session).update(job_id, payload)
    except JobNotFound as exc:
        raise HTTPException(status_code=404, detail="Job not found") from exc
    except InvalidJobTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return JobRead.model_validate(job)
