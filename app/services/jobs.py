from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Job, JobKind, JobStatus
from app.schemas import JobCreate, JobUpdate


class JobNotFound(LookupError):
    pass


class InvalidJobTransition(ValueError):
    pass


TERMINAL_STATUSES = {
    JobStatus.SUCCEEDED,
    JobStatus.FAILED,
    JobStatus.CANCELLED,
}

ALLOWED_TRANSITIONS = {
    JobStatus.QUEUED: {
        JobStatus.RUNNING,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    },
    JobStatus.RUNNING: TERMINAL_STATUSES,
    JobStatus.SUCCEEDED: set(),
    JobStatus.FAILED: set(),
    JobStatus.CANCELLED: set(),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class JobService:
    def __init__(self, session: Session):
        self.session = session

    def create(self, payload: JobCreate) -> Job:
        job = Job(
            kind=payload.kind,
            status=JobStatus.QUEUED,
            progress=0,
            parameters=payload.parameters,
            message=payload.message or "Waiting for a worker",
        )
        self.session.add(job)
        self.session.commit()
        self.session.refresh(job)
        return job

    def get(self, job_id: str) -> Job:
        job = self.session.get(Job, job_id)
        if job is None:
            raise JobNotFound(job_id)
        return job

    def list(
        self,
        *,
        status: JobStatus | None = None,
        limit: int = 25,
    ) -> list[Job]:
        statement = select(Job).order_by(Job.created_at.desc()).limit(limit)
        if status is not None:
            statement = statement.where(Job.status == status)
        return list(self.session.scalars(statement))

    def counts(self) -> dict[str, int]:
        statement = select(Job.status, func.count(Job.id)).group_by(Job.status)
        counts = {status.value: 0 for status in JobStatus}
        for status, count in self.session.execute(statement):
            counts[status.value] = count
        return counts

    def update(self, job_id: str, payload: JobUpdate) -> Job:
        job = self.get(job_id)
        old_status = job.status
        new_status = payload.status

        if (
            new_status != old_status
            and new_status not in ALLOWED_TRANSITIONS[old_status]
        ):
            raise InvalidJobTransition(
                f"Cannot transition a job from {old_status.value} to {new_status.value}"
            )
        if old_status in TERMINAL_STATUSES:
            raise InvalidJobTransition(
                f"Cannot update a terminal {old_status.value} job"
            )
        if payload.progress is not None and payload.progress < job.progress:
            raise InvalidJobTransition("Job progress cannot decrease")

        now = utc_now()
        if new_status == JobStatus.RUNNING and job.started_at is None:
            job.started_at = now
        if new_status in TERMINAL_STATUSES:
            job.finished_at = now

        job.status = new_status
        if payload.progress is not None:
            job.progress = payload.progress
        if new_status == JobStatus.SUCCEEDED:
            job.progress = 100
        if payload.message is not None:
            job.message = payload.message
        if payload.result is not None:
            job.result = payload.result
        if payload.error is not None:
            job.error = payload.error
        job.updated_at = now

        self.session.commit()
        self.session.refresh(job)
        return job


def system_job_payload(message: str) -> JobCreate:
    return JobCreate(kind=JobKind.SYSTEM, message=message)
