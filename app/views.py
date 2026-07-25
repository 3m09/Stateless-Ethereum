from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.config import Settings
from app.dependencies import get_database_session
from app.schemas import redact_secrets
from app.services.jobs import JobNotFound, JobService

router = APIRouter(include_in_schema=False)


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    session: Session = Depends(get_database_session),
) -> HTMLResponse:
    settings: Settings = request.app.state.settings
    service = JobService(session)
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "jobs": service.list(limit=settings.dashboard_job_limit),
            "counts": service.counts(),
            "settings": settings,
        },
    )


@router.get("/partials/jobs", response_class=HTMLResponse)
async def jobs_partial(
    request: Request,
    session: Session = Depends(get_database_session),
) -> HTMLResponse:
    settings: Settings = request.app.state.settings
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="partials/jobs_table.html",
        context={
            "jobs": JobService(session).list(limit=settings.dashboard_job_limit),
        },
    )


@router.get("/jobs/{job_id}", response_class=HTMLResponse)
async def job_detail(
    job_id: str,
    request: Request,
    session: Session = Depends(get_database_session),
) -> HTMLResponse:
    try:
        job = JobService(session).get(job_id)
    except JobNotFound as exc:
        raise HTTPException(status_code=404, detail="Job not found") from exc

    return request.app.state.templates.TemplateResponse(
        request=request,
        name="job_detail.html",
        context={
            "job": job,
            "safe_job_parameters": redact_secrets(job.parameters),
        },
    )
