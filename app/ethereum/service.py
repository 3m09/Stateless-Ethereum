from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

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
    EthereumRPCRequestError,
    default_rpc_factory,
    rpc_provider_label,
)
from app.ethereum.schemas import EthereumImportCreate
from app.limits import (
    DEFAULT_ACCOUNT_PAGE_SIZE,
    MAX_EXPERIMENT_KEYS,
    is_power_of_two_account_count,
)
from app.models import (
    AddressSource,
    DatasetStatus,
    EthereumAccount,
    EthereumDataset,
    Job,
    JobKind,
    JobStatus,
    StateMode,
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


class LocalJSONImportError(ValueError):
    pass


MAX_LOCAL_JSON_BYTES = 16 * 1024 * 1024


class JSONObjectPairs(list):
    """Marker used to retain duplicate JSON object keys during parsing."""


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


def redact_rpc_urls(message: str, settings: Settings) -> str:
    for url, replacement in (
        (settings.ethereum_rpc_url, "<configured data RPC>"),
        (settings.ethereum_proof_rpc_url, "<configured proof RPC>"),
    ):
        if url:
            message = message.replace(url, replacement)
    return message


def parse_local_trie_json(content: bytes) -> list[dict[str, str]]:
    if not content:
        raise LocalJSONImportError("The uploaded JSON file is empty")
    if len(content) > MAX_LOCAL_JSON_BYTES:
        raise LocalJSONImportError("The uploaded JSON file exceeds the 16 MiB limit")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LocalJSONImportError("The uploaded file must be UTF-8 JSON") from exc
    try:
        payload = json.loads(text, object_pairs_hook=JSONObjectPairs)
    except json.JSONDecodeError as exc:
        raise LocalJSONImportError(
            f"Invalid JSON at line {exc.lineno}, column {exc.colno}"
        ) from exc
    if not isinstance(payload, JSONObjectPairs):
        raise LocalJSONImportError(
            "Top-level JSON must be an object mapping trie keys to RLP values"
        )
    if not 1 <= len(payload) <= MAX_EXPERIMENT_KEYS:
        raise LocalJSONImportError(
            f"JSON must contain between 1 and {MAX_EXPERIMENT_KEYS} entries"
        )
    if not is_power_of_two_account_count(len(payload)):
        raise LocalJSONImportError(
            "JSON entry count must be a power of two from 1 through 2048"
        )

    parsed: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, pair in enumerate(payload, start=1):
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise LocalJSONImportError(f"Entry {index} is not a key/value pair")
        secure_key, account_rlp = pair
        if not isinstance(secure_key, str) or not isinstance(account_rlp, str):
            raise LocalJSONImportError(
                f"Entry {index} key and value must both be hexadecimal strings"
            )
        try:
            key_bytes = bytes.fromhex(secure_key.removeprefix("0x"))
        except ValueError as exc:
            raise LocalJSONImportError(
                f"Entry {index} has an invalid hexadecimal trie key"
            ) from exc
        if not secure_key.startswith("0x") or len(key_bytes) != 32:
            raise LocalJSONImportError(
                f"Entry {index} trie key must be a 0x-prefixed 32-byte value"
            )
        normalized_key = f"0x{key_bytes.hex()}"
        if normalized_key in seen:
            raise LocalJSONImportError(
                f"Entry {index} duplicates trie key {normalized_key}"
            )
        seen.add(normalized_key)

        try:
            value_bytes = bytes.fromhex(account_rlp.removeprefix("0x"))
            decoded = rlp.decode(value_bytes)
        except (ValueError, rlp.exceptions.DecodingError) as exc:
            raise LocalJSONImportError(
                f"Entry {index} has an invalid RLP account value"
            ) from exc
        if (
            not account_rlp.startswith("0x")
            or not isinstance(decoded, list)
            or len(decoded) != 4
            or not all(isinstance(item, bytes) for item in decoded)
        ):
            raise LocalJSONImportError(
                f"Entry {index} must encode [nonce, balance, storageRoot, codeHash]"
            )
        nonce, balance, storage_root, code_hash = decoded
        if len(storage_root) != 32 or len(code_hash) != 32:
            raise LocalJSONImportError(
                f"Entry {index} storageRoot and codeHash must each be 32 bytes"
            )
        parsed.append(
            {
                "secure_trie_key": normalized_key,
                "account_rlp": f"0x{value_bytes.hex()}",
                "nonce": str(int.from_bytes(nonce, "big")),
                "balance": str(int.from_bytes(balance, "big")),
                "storage_root": f"0x{storage_root.hex()}",
                "code_hash": f"0x{code_hash.hex()}",
            }
        )
    return parsed


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
            rpc_provider=rpc_provider_label(
                settings.ethereum_proof_rpc_url
                or settings.ethereum_rpc_url
                or ""
            ),
            requested_block=str(payload.block),
            address_source=payload.address_source,
            state_mode=payload.state_mode,
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
        limit: int = DEFAULT_ACCOUNT_PAGE_SIZE,
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


def create_local_import_records(
    *,
    session: Session,
    artifacts: ArtifactStore,
    settings: Settings,
    name: str,
    original_filename: str | None,
    content: bytes,
) -> tuple[EthereumDataset, Job]:
    parsed_accounts = parse_local_trie_json(content)
    filename = Path(original_filename or "uploaded.json").name[:255]
    content_sha256 = hashlib.sha256(content).hexdigest()
    count = len(parsed_accounts)

    job = JobService(session).create(
        JobCreate(
            kind=JobKind.ETHEREUM_IMPORT,
            parameters={
                "source": AddressSource.LOCAL_JSON.value,
                "filename": filename,
                "entry_count": count,
                "sha256": content_sha256,
            },
            message="Local JSON import queued",
        )
    )
    dataset = EthereumDataset(
        name=name,
        network="local",
        rpc_provider="local-json",
        requested_block="local",
        address_source=AddressSource.LOCAL_JSON,
        state_mode=StateMode.LOCAL_IMPORT,
        requested_account_count=count,
        imported_account_count=count,
        scan_depth=0,
        observed_state_root_count=0,
        status=DatasetStatus.READY,
        job_id=job.id,
        fetched_at=utc_now(),
    )
    session.add(dataset)
    session.commit()
    session.refresh(dataset)

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
    job = JobService(session).update(
        job.id,
        JobUpdate(
            status=JobStatus.RUNNING,
            progress=10,
            message="Validating and persisting local trie data",
        ),
    )
    workspace = artifacts.path_for("datasets", dataset.id, create=True)
    normalized_trie_kv = {
        account["secure_trie_key"]: account["account_rlp"]
        for account in parsed_accounts
    }
    uploaded_path = workspace / "uploaded_trie_data.json"
    artifacts.write_json(uploaded_path, normalized_trie_kv)

    artifact_accounts: list[dict] = []
    for parsed in parsed_accounts:
        session.add(
            EthereumAccount(
                dataset_id=dataset.id,
                address=None,
                secure_trie_key=parsed["secure_trie_key"],
                account_rlp=parsed["account_rlp"],
                nonce=parsed["nonce"],
                balance=parsed["balance"],
                storage_root=parsed["storage_root"],
                code_hash=parsed["code_hash"],
                account_proof=[],
                proof_node_count=0,
                proof_state_root=None,
            )
        )
        artifact_accounts.append(
            {
                "address": None,
                **parsed,
                "account_proof": [],
                "proof_state_root": None,
            }
        )

    snapshot_path = workspace / "snapshot.json"
    artifacts.write_json(
        snapshot_path,
        {
            "schema_version": 2,
            "dataset_id": dataset.id,
            "network": dataset.network,
            "chain_id": None,
            "rpc_provider": dataset.rpc_provider,
            "requested_block": dataset.requested_block,
            "block": None,
            "address_source": dataset.address_source.value,
            "state_mode": dataset.state_mode.value,
            "requested_account_count": count,
            "imported_account_count": count,
            "observed_state_root_count": 0,
            "observed_state_roots": [],
            "source_file": {
                "original_filename": filename,
                "sha256": content_sha256,
                "normalized_artifact": str(
                    uploaded_path.relative_to(artifacts.root)
                ),
            },
            "accounts": artifact_accounts,
            "trie_kv": normalized_trie_kv,
            "fetched_at": dataset.fetched_at,
            "root_scope_note": (
                "Values were imported from local JSON without original "
                "addresses or eth_getProof authentication paths. They are "
                "validly decoded account RLP values but are not independently "
                "authenticated by this application."
            ),
        },
    )
    dataset.artifact_path = str(snapshot_path.relative_to(artifacts.root))
    session.commit()

    job = JobService(session).update(
        job.id,
        JobUpdate(
            status=JobStatus.SUCCEEDED,
            progress=100,
            message=f"Imported {count} local trie key/value pairs",
            result={
                "dataset_id": dataset.id,
                "account_count": count,
                "state_mode": dataset.state_mode.value,
                "source_sha256": content_sha256,
                "artifact_path": dataset.artifact_path,
            },
        ),
    )
    _save_job_manifest(artifacts, job, dataset)
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
                candidate_count = payload.account_count + max(
                    256,
                    payload.account_count // 2,
                )
                addresses = await rpc.discover_recent_addresses(
                    block_number=block.number,
                    account_count=candidate_count,
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
                    message=(
                        f"Fetching up to {payload.account_count} account "
                        f"proofs from {len(addresses)} candidates"
                    ),
                ),
            )

            artifact_accounts: list[dict] = []
            trie_kv: dict[str, str] = {}
            observed_state_roots: set[str] = set()
            failed_accounts: list[dict[str, str]] = []
            proof_block_identifier: str | int = (
                block.number if payload.state_mode == StateMode.PINNED else "latest"
            )
            concurrency = settings.ethereum_proof_concurrency
            progress_step = max(1, (payload.account_count + 19) // 20)
            persistence_step = max(100, concurrency * 4)
            address_cursor = 0

            while (
                address_cursor < len(addresses)
                and len(artifact_accounts) < payload.account_count
            ):
                remaining = payload.account_count - len(artifact_accounts)
                batch_size = min(concurrency, remaining)
                batch = addresses[address_cursor : address_cursor + batch_size]
                address_cursor += len(batch)
                results = await asyncio.gather(
                    *(
                        rpc.get_account_proof(address, proof_block_identifier)
                        for address in batch
                    ),
                    return_exceptions=True,
                )

                for address, result in zip(batch, results, strict=True):
                    if len(artifact_accounts) >= payload.account_count:
                        break
                    if isinstance(result, asyncio.CancelledError):
                        raise result
                    if isinstance(result, EthereumRPCRequestError):
                        failed_accounts.append(
                            {
                                "address": address,
                                "error": redact_rpc_urls(str(result), settings),
                            }
                        )
                        continue
                    if isinstance(result, BaseException):
                        raise result
                    proof = result

                    if (
                        payload.state_mode == StateMode.PINNED
                        and proof.proof_state_root.lower() != block.state_root.lower()
                    ):
                        raise ChainReorganizationError(
                            "Account proof root does not match pinned state root "
                            f"for {address}: expected {block.state_root}, received "
                            f"{proof.proof_state_root}"
                        )

                    secure_key, account_rlp = encode_account(proof)
                    imported_count = len(artifact_accounts) + 1
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
                        proof_state_root=proof.proof_state_root,
                    )
                    session.add(account)
                    dataset.imported_account_count = imported_count

                    trie_kv[secure_key] = account_rlp
                    observed_state_roots.add(proof.proof_state_root)
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
                            "proof_state_root": proof.proof_state_root,
                        }
                    )
                    if (
                        imported_count % progress_step == 0
                        or imported_count == payload.account_count
                    ):
                        progress = 15 + round(
                            75 * imported_count / payload.account_count
                        )
                        job = jobs.update(
                            job.id,
                            JobUpdate(
                                status=JobStatus.RUNNING,
                                progress=progress,
                                message=(
                                    f"Fetched account proof {imported_count} of "
                                    f"{payload.account_count}"
                                ),
                            ),
                        )
                    elif imported_count % persistence_step == 0:
                        session.commit()

            if not artifact_accounts:
                raise NoAddressesFoundError(
                    "No account proofs could be fetched. Check the configured "
                    "proof RPC endpoint and create a new dataset."
                )

            if payload.state_mode == StateMode.PINNED:
                confirmation = await rpc.pin_block(block.number)
                if confirmation.hash != block.hash:
                    raise ChainReorganizationError(
                        f"Block {block.number} changed during import; retry the dataset"
                    )
                collection_end = confirmation
            else:
                collection_end = await rpc.pin_block("latest")

            snapshot_path = artifacts.path_for("datasets", dataset.id) / "snapshot.json"
            dataset.observed_state_root_count = len(observed_state_roots)
            session.commit()
            artifacts.write_json(
                snapshot_path,
                {
                    "schema_version": 2,
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
                    "state_mode": dataset.state_mode.value,
                    "proof_concurrency": concurrency,
                    "requested_account_count": dataset.requested_account_count,
                    "imported_account_count": len(artifact_accounts),
                    "observed_state_root_count": len(observed_state_roots),
                    "observed_state_roots": sorted(observed_state_roots),
                    "collection_end_block": {
                        "number": collection_end.number,
                        "hash": collection_end.hash,
                        "state_root": collection_end.state_root,
                        "timestamp": collection_end.timestamp,
                    },
                    "failed_account_count": len(failed_accounts),
                    "failed_accounts": failed_accounts,
                    "accounts": artifact_accounts,
                    "trie_kv": trie_kv,
                    "fetched_at": utc_now(),
                    "root_scope_note": (
                        (
                            "All account proofs authenticate against the pinned "
                            "Ethereum state root. "
                        )
                        if payload.state_mode == StateMode.PINNED
                        else (
                            "Account proofs were fetched from rolling latest "
                            "state and may authenticate against multiple roots. "
                        )
                    )
                    + (
                        "A reconstructed experimental root covers only this "
                        "partial sample and is not Ethereum's full state root."
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
                    message=(
                        f"Imported {len(artifact_accounts)} of "
                        f"{payload.account_count} requested account proofs"
                    ),
                    result={
                        "dataset_id": dataset.id,
                        "block_number": block.number,
                        "block_hash": block.hash,
                        "state_root": block.state_root,
                        "account_count": len(artifact_accounts),
                        "requested_account_count": payload.account_count,
                        "state_mode": payload.state_mode.value,
                        "proof_concurrency": concurrency,
                        "observed_state_root_count": len(observed_state_roots),
                        "failed_account_count": len(failed_accounts),
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
            message = redact_rpc_urls(message, settings)
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
