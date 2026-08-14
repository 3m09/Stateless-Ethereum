from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.artifacts import ArtifactStore
from app.dependencies import get_artifact_store, get_database_session
from app.ethereum.schemas import (
    EthereumAccountRead,
    EthereumDatasetRead,
    EthereumImportAccepted,
    EthereumImportCreate,
    LocalEthereumImportCreate,
)
from app.ethereum.service import (
    MAX_LOCAL_JSON_BYTES,
    DatasetNotFound,
    EthereumDatasetService,
    LocalJSONImportError,
    create_import_records,
    create_local_import_records,
    schedule_import,
)
from app.limits import DEFAULT_ACCOUNT_PAGE_SIZE, MAX_EXPERIMENT_KEYS
from app.schemas import JobRead

router = APIRouter(prefix="/api/v1/ethereum", tags=["ethereum data"])


@router.post(
    "/imports",
    response_model=EthereumImportAccepted,
    status_code=202,
)
async def create_ethereum_import(
    payload: EthereumImportCreate,
    request: Request,
    session: Session = Depends(get_database_session),
    artifacts: ArtifactStore = Depends(get_artifact_store),
) -> EthereumImportAccepted:
    settings = request.app.state.settings
    if not settings.ethereum_rpc_url:
        raise HTTPException(
            status_code=503,
            detail="STATELESS_ETHEREUM_RPC_URL is not configured",
        )

    dataset, job = create_import_records(
        session=session,
        artifacts=artifacts,
        settings=settings,
        payload=payload,
    )
    schedule_import(request.app, dataset.id, payload)
    return EthereumImportAccepted(
        dataset=EthereumDatasetRead.model_validate(dataset),
        job=JobRead.model_validate(job),
    )


@router.post(
    "/imports/json",
    response_model=EthereumImportAccepted,
    status_code=201,
)
async def create_local_ethereum_import(
    request: Request,
    name: str = Form(...),
    data_file: UploadFile = File(...),
    session: Session = Depends(get_database_session),
    artifacts: ArtifactStore = Depends(get_artifact_store),
) -> EthereumImportAccepted:
    try:
        payload = LocalEthereumImportCreate(name=name)
        content = await data_file.read(MAX_LOCAL_JSON_BYTES + 1)
        dataset, job = create_local_import_records(
            session=session,
            artifacts=artifacts,
            settings=request.app.state.settings,
            name=payload.name,
            original_filename=data_file.filename,
            content=content,
        )
    except (ValidationError, LocalJSONImportError) as exc:
        detail = (
            exc.errors(include_url=False)
            if isinstance(exc, ValidationError)
            else str(exc)
        )
        raise HTTPException(status_code=422, detail=detail) from exc
    finally:
        await data_file.close()
    return EthereumImportAccepted(
        dataset=EthereumDatasetRead.model_validate(dataset),
        job=JobRead.model_validate(job),
    )


@router.get("/datasets", response_model=list[EthereumDatasetRead])
async def list_ethereum_datasets(
    limit: int = Query(default=50, ge=1, le=200),
    session: Session = Depends(get_database_session),
) -> list[EthereumDatasetRead]:
    datasets = EthereumDatasetService(session).list(limit=limit)
    return [EthereumDatasetRead.model_validate(dataset) for dataset in datasets]


@router.get(
    "/datasets/{dataset_id}",
    response_model=EthereumDatasetRead,
)
async def get_ethereum_dataset(
    dataset_id: str,
    session: Session = Depends(get_database_session),
) -> EthereumDatasetRead:
    try:
        dataset = EthereumDatasetService(session).get(dataset_id)
    except DatasetNotFound as exc:
        raise HTTPException(status_code=404, detail="Dataset not found") from exc
    return EthereumDatasetRead.model_validate(dataset)


@router.get(
    "/datasets/{dataset_id}/accounts",
    response_model=list[EthereumAccountRead],
)
async def list_ethereum_accounts(
    dataset_id: str,
    limit: int = Query(
        default=DEFAULT_ACCOUNT_PAGE_SIZE,
        ge=1,
        le=MAX_EXPERIMENT_KEYS,
    ),
    session: Session = Depends(get_database_session),
) -> list[EthereumAccountRead]:
    try:
        accounts = EthereumDatasetService(session).accounts(
            dataset_id,
            limit=limit,
        )
    except DatasetNotFound as exc:
        raise HTTPException(status_code=404, detail="Dataset not found") from exc
    return [EthereumAccountRead.model_validate(account) for account in accounts]
