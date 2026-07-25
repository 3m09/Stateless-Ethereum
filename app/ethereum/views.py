import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.artifacts import ArtifactStore
from app.dependencies import get_artifact_store, get_database_session
from app.ethereum.rpc import rpc_provider_label
from app.ethereum.schemas import EthereumImportCreate
from app.ethereum.service import (
    DatasetNotFound,
    EthereumDatasetService,
    create_import_records,
    schedule_import,
)
from app.models import AddressSource

router = APIRouter(include_in_schema=False)


def split_addresses(value: str) -> list[str]:
    return [address for address in re.split(r"[\s,;]+", value.strip()) if address]


def data_page_context(
    request: Request,
    session: Session,
    *,
    form_values: dict | None = None,
    errors: list[dict] | None = None,
) -> dict:
    settings = request.app.state.settings
    return {
        "section": "data",
        "settings": settings,
        "rpc_configured": bool(settings.ethereum_rpc_url),
        "rpc_provider": (
            rpc_provider_label(settings.ethereum_rpc_url)
            if settings.ethereum_rpc_url
            else None
        ),
        "datasets": EthereumDatasetService(session).list(limit=50),
        "form_values": form_values or {},
        "errors": errors or [],
    }


@router.get("/data", response_class=HTMLResponse)
async def data_page(
    request: Request,
    session: Session = Depends(get_database_session),
) -> HTMLResponse:
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="data.html",
        context=data_page_context(request, session),
    )


@router.post("/data/imports", response_class=HTMLResponse)
async def create_data_import(
    request: Request,
    name: str = Form(...),
    block: str = Form("latest"),
    address_source: str = Form(AddressSource.RECENT_TRANSACTIONS.value),
    addresses: str = Form(""),
    account_count: int = Form(25),
    scan_depth: int = Form(20),
    session: Session = Depends(get_database_session),
    artifacts: ArtifactStore = Depends(get_artifact_store),
):
    settings = request.app.state.settings
    form_values = {
        "name": name,
        "block": block,
        "address_source": address_source,
        "addresses": addresses,
        "account_count": account_count,
        "scan_depth": scan_depth,
    }
    if not settings.ethereum_rpc_url:
        return request.app.state.templates.TemplateResponse(
            request=request,
            name="data.html",
            context=data_page_context(
                request,
                session,
                form_values=form_values,
                errors=[
                    {
                        "msg": (
                            "Configure STATELESS_ETHEREUM_RPC_URL before "
                            "starting an import"
                        )
                    }
                ],
            ),
            status_code=503,
        )

    try:
        payload = EthereumImportCreate(
            name=name,
            block=block,
            address_source=address_source,
            addresses=split_addresses(addresses),
            account_count=account_count,
            scan_depth=scan_depth,
        )
    except ValidationError as exc:
        return request.app.state.templates.TemplateResponse(
            request=request,
            name="data.html",
            context=data_page_context(
                request,
                session,
                form_values=form_values,
                errors=exc.errors(include_url=False),
            ),
            status_code=422,
        )

    dataset, _job = create_import_records(
        session=session,
        artifacts=artifacts,
        settings=settings,
        payload=payload,
    )
    schedule_import(request.app, dataset.id, payload)
    return RedirectResponse(url=f"/data/{dataset.id}", status_code=303)


@router.get("/data/{dataset_id}", response_class=HTMLResponse)
async def dataset_detail(
    dataset_id: str,
    request: Request,
    session: Session = Depends(get_database_session),
) -> HTMLResponse:
    service = EthereumDatasetService(session)
    try:
        dataset = service.get(dataset_id)
        accounts = service.accounts(dataset_id)
    except DatasetNotFound as exc:
        raise HTTPException(status_code=404, detail="Dataset not found") from exc

    return request.app.state.templates.TemplateResponse(
        request=request,
        name="dataset_detail.html",
        context={
            "section": "data",
            "dataset": dataset,
            "accounts": accounts,
        },
    )


@router.get(
    "/partials/data/{dataset_id}/summary",
    response_class=HTMLResponse,
)
async def dataset_summary_partial(
    dataset_id: str,
    request: Request,
    session: Session = Depends(get_database_session),
) -> HTMLResponse:
    service = EthereumDatasetService(session)
    try:
        dataset = service.get(dataset_id)
    except DatasetNotFound as exc:
        raise HTTPException(status_code=404, detail="Dataset not found") from exc

    return request.app.state.templates.TemplateResponse(
        request=request,
        name="partials/dataset_summary.html",
        context={"dataset": dataset},
    )
