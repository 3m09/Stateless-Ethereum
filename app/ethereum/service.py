from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone

import rlp
from eth_utils import keccak
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.artifacts import ArtifactStore
from app.config import Settings
from app.database import Database
from app.ethereum.rpc import (
    AccountProof,
    EthereumRPC,
    default_rpc_factory,
    rpc_provider_label,
)
from app.ethereum.schemas import EthereumImportCreate
from app.models import (
    AddressSource,
    DatasetStatus,
    EthereumAccount,
    EthereumDataset,
    Job,
    JobKind,
    JobStatus,
)
from app.schemas import JobCreate, JobUpdate
from app.services.jobs import JobService

RPCFactory = Callable[[Settings], EthereumRPC]


class DatasetNotFound(LookupError):
    pass


class ChainMismatchError(RuntimeError):
    pass


class ChainReorganizationError(RuntimeError):
    pass


class NoAddressesFoundError(RuntimeError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def hex_bytes(value: str) -> bytes:
    return bytes.fromhex(value.removeprefix("0x"))


def encode_account(proof: AccountProof) -> tuple[str, str]:
    secure_key = keccak(hex_bytes(proof.address))
    account_value = rlp.encode(
        [
            proof.nonce,
            proof.balance,
            hex_bytes(proof.storage_root),
            hex_bytes(proof.code_hash),
        ]
    )
    return f"0x{secure_key.hex()}", f"0x{account_value.hex()}"


class EthereumDatasetService:
    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        payload: EthereumImportCreate,
        job: Job,
        settings: Settings,
    ) -> EthereumDataset:
        dataset = EthereumDataset(
            name=payload.name,
            network=settings.ethereum_network,
            rpc_provider=rpc_provider_label(settings.ethereum_rpc_url or ""),
            requested_block=str(payload.block),
            address_source=payload.address_source,
            requested_account_count=payload.account_count,
            imported_account_count=0,
            scan_depth=payload.scan_depth,
            status=DatasetStatus.QUEUED,
            job_id=job.id,
        )
        self.session.add(dataset)
        self.session.commit()
        self.session.refresh(dataset)
        return dataset

    def get(self, dataset_id: str) -> EthereumDataset:
        dataset = self.session.get(EthereumDataset, dataset_id)
        if dataset is None:
            raise DatasetNotFound(dataset_id)
        return dataset

    def list(self, limit: int = 50) -> list[EthereumDataset]:
        statement = (
            select(EthereumDataset)
            .order_by(EthereumDataset.created_at.desc())
            .limit(limit)
        )
        return list(self.session.scalars(statement))

    def accounts(
        self,
        dataset_id: str,
        *,
        limit: int = 250,
    ) -> list[EthereumAccount]:
        self.get(dataset_id)
        statement = (
            select(EthereumAccount)
            .where(EthereumAccount.dataset_id == dataset_id)
            .order_by(EthereumAccount.created_at.asc())
            .limit(limit)
        )
        return list(self.session.scalars(statement))


def create_import_records(
    *,
    session: Session,
    artifacts: ArtifactStore,
    settings: Settings,
    payload: EthereumImportCreate,
) -> tuple[EthereumDataset, Job]:
    job = JobService(session).create(
        JobCreate(
            kind=JobKind.ETHEREUM_IMPORT,
            parameters=payload.model_dump(mode="json"),
            message="Ethereum import queued",
        )
    )
    dataset = EthereumDatasetService(session).create(payload, job, settings)

    artifacts.initialize_job(
        job.id,
        {
            "job_id": job.id,
            "dataset_id": dataset.id,
            "kind": job.kind.value,
            "status": job.status.value,
            "parameters": job.parameters,
            "created_at": job.created_at,
        },
    )
    dataset_workspace = artifacts.path_for(
        "datasets",
        dataset.id,
        create=True,
    )
    artifacts.write_json(
        dataset_workspace / "request.json",
        {
            "schema_version": 1,
            "dataset_id": dataset.id,
            "job_id": job.id,
            "network": dataset.network,
            "rpc_provider": dataset.rpc_provider,
            "request": payload.model_dump(mode="json"),
            "created_at": dataset.created_at,
        },
    )
    return dataset, job


def schedule_import(
    application: FastAPI,
    dataset_id: str,
    payload: EthereumImportCreate,
) -> asyncio.Task:
    task = asyncio.create_task(
        run_import(
            database=application.state.database,
            artifacts=application.state.artifacts,
            settings=application.state.settings,
            rpc_factory=application.state.ethereum_rpc_factory,
            dataset_id=dataset_id,
            payload=payload,
        ),
        name=f"ethereum-import-{dataset_id}",
    )
    application.state.background_tasks.add(task)
    task.add_done_callback(application.state.background_tasks.discard)
    return task


def _save_job_manifest(
    artifacts: ArtifactStore,
    job: Job,
    dataset: EthereumDataset,
) -> None:
    workspace = artifacts.path_for("jobs", job.id)
    artifacts.write_json(
        workspace / "manifest.json",
        {
            "job_id": job.id,
            "dataset_id": dataset.id,
            "kind": job.kind.value,
            "status": job.status.value,
            "progress": job.progress,
            "message": job.message,
            "parameters": job.parameters,
            "result": job.result,
            "error": job.error,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
        },
    )


async def run_import(
    *,
    database: Database,
    artifacts: ArtifactStore,
    settings: Settings,
    rpc_factory: RPCFactory = default_rpc_factory,
    dataset_id: str,
    payload: EthereumImportCreate,
) -> None:
    rpc: EthereumRPC | None = None

    with database.session() as session:
        datasets = EthereumDatasetService(session)
        jobs = JobService(session)
        dataset = datasets.get(dataset_id)
        job = jobs.get(dataset.job_id)

        try:
            dataset.status = DatasetStatus.IMPORTING
            session.commit()
            job = jobs.update(
                job.id,
                JobUpdate(
                    status=JobStatus.RUNNING,
                    progress=2,
                    message="Connecting to the configured Ethereum RPC",
                ),
            )

            rpc = rpc_factory(settings)
            chain_id = await rpc.chain_id()
            if chain_id != settings.ethereum_expected_chain_id:
                raise ChainMismatchError(
                    f"Expected chain ID {settings.ethereum_expected_chain_id}, "
                    f"received {chain_id}"
                )

            block = await rpc.pin_block(payload.block)
            dataset.chain_id = chain_id
            dataset.block_number = block.number
            dataset.block_hash = block.hash
            dataset.state_root = block.state_root
            dataset.block_timestamp = block.timestamp
            session.commit()
            job = jobs.update(
                job.id,
                JobUpdate(
                    status=JobStatus.RUNNING,
                    progress=10,
                    message=f"Pinned block {block.number}",
                ),
            )

            if payload.address_source == AddressSource.EXPLICIT:
                addresses = [
                    rpc.normalize_address(address) for address in payload.addresses
                ]
            else:
                addresses = await rpc.discover_recent_addresses(
                    block_number=block.number,
                    account_count=payload.account_count,
                    scan_depth=payload.scan_depth,
                )

            if not addresses:
                raise NoAddressesFoundError(
                    "No account addresses were found in the requested range"
                )

            job = jobs.update(
                job.id,
                JobUpdate(
                    status=JobStatus.RUNNING,
                    progress=15,
                    message=f"Fetching proofs for {len(addresses)} accounts",
                ),
            )

            artifact_accounts: list[dict] = []
            trie_kv: dict[str, str] = {}
            for index, address in enumerate(addresses, start=1):
                proof = await rpc.get_account_proof(address, block.number)
                secure_key, account_rlp = encode_account(proof)
                account = EthereumAccount(
                    dataset_id=dataset.id,
                    address=proof.address,
                    secure_trie_key=secure_key,
                    account_rlp=account_rlp,
                    nonce=str(proof.nonce),
                    balance=str(proof.balance),
                    storage_root=proof.storage_root,
                    code_hash=proof.code_hash,
                    account_proof=proof.account_proof,
                    proof_node_count=len(proof.account_proof),
                )
                session.add(account)
                dataset.imported_account_count = index
                session.commit()

                trie_kv[secure_key] = account_rlp
                artifact_accounts.append(
                    {
                        "address": proof.address,
                        "secure_trie_key": secure_key,
                        "account_rlp": account_rlp,
                        "nonce": str(proof.nonce),
                        "balance": str(proof.balance),
                        "storage_root": proof.storage_root,
                        "code_hash": proof.code_hash,
                        "account_proof": proof.account_proof,
                    }
                )
                progress = 15 + round(75 * index / len(addresses))
                job = jobs.update(
                    job.id,
                    JobUpdate(
                        status=JobStatus.RUNNING,
                        progress=progress,
                        message=f"Fetched account proof {index} of {len(addresses)}",
                    ),
                )

            confirmation = await rpc.pin_block(block.number)
            if confirmation.hash != block.hash:
                raise ChainReorganizationError(
                    f"Block {block.number} changed during import; retry the dataset"
                )

            snapshot_path = artifacts.path_for("datasets", dataset.id) / "snapshot.json"
            artifacts.write_json(
                snapshot_path,
                {
                    "schema_version": 1,
                    "dataset_id": dataset.id,
                    "network": dataset.network,
                    "chain_id": chain_id,
                    "rpc_provider": dataset.rpc_provider,
                    "requested_block": dataset.requested_block,
                    "block": {
                        "number": block.number,
                        "hash": block.hash,
                        "state_root": block.state_root,
                        "timestamp": block.timestamp,
                    },
                    "address_source": dataset.address_source.value,
                    "requested_account_count": dataset.requested_account_count,
                    "imported_account_count": len(artifact_accounts),
                    "accounts": artifact_accounts,
                    "trie_kv": trie_kv,
                    "fetched_at": utc_now(),
                    "root_scope_note": (
                        "This dataset contains authentic account states from a "
                        "partial sample. A reconstructed root is not the full "
                        "Ethereum block state root."
                    ),
                },
            )

            dataset.status = DatasetStatus.READY
            dataset.fetched_at = utc_now()
            dataset.artifact_path = str(snapshot_path.relative_to(artifacts.root))
            session.commit()
            job = jobs.update(
                job.id,
                JobUpdate(
                    status=JobStatus.SUCCEEDED,
                    progress=100,
                    message=f"Imported {len(artifact_accounts)} account proofs",
                    result={
                        "dataset_id": dataset.id,
                        "block_number": block.number,
                        "block_hash": block.hash,
                        "state_root": block.state_root,
                        "account_count": len(artifact_accounts),
                        "artifact_path": dataset.artifact_path,
                    },
                ),
            )
            _save_job_manifest(artifacts, job, dataset)
        except asyncio.CancelledError:
            message = "Ethereum import stopped during application shutdown"
            dataset.status = DatasetStatus.FAILED
            dataset.error = message
            session.commit()
            if job.status not in {
                JobStatus.SUCCEEDED,
                JobStatus.FAILED,
                JobStatus.CANCELLED,
            }:
                job = jobs.update(
                    job.id,
                    JobUpdate(
                        status=JobStatus.FAILED,
                        message=message,
                        error=message,
                    ),
                )
            _save_job_manifest(artifacts, job, dataset)
            raise
        except Exception as exc:
            message = str(exc) or type(exc).__name__
            if settings.ethereum_rpc_url:
                message = message.replace(
                    settings.ethereum_rpc_url,
                    "<configured RPC>",
                )
            dataset.status = DatasetStatus.FAILED
            dataset.error = message
            session.commit()
            if job.status not in {
                JobStatus.SUCCEEDED,
                JobStatus.FAILED,
                JobStatus.CANCELLED,
            }:
                job = jobs.update(
                    job.id,
                    JobUpdate(
                        status=JobStatus.FAILED,
                        message="Ethereum import failed",
                        error=message,
                    ),
                )
            _save_job_manifest(artifacts, job, dataset)
        finally:
            if rpc is not None:
                await rpc.close()
