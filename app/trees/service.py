from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from time import perf_counter

from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.artifacts import ArtifactStore
from app.database import Database
from app.models import (
    DatasetStatus,
    EthereumAccount,
    EthereumDataset,
    GeneratedTree,
    Job,
    JobKind,
    JobStatus,
    TreeStatus,
)
from app.schemas import JobCreate, JobUpdate
from app.services.jobs import JobService
from app.trees.engine import (
    TreeBuildOutput,
    build_merkle_patricia_tree,
    build_poseidon_merkle_patricia_tree,
    build_verkle_tree,
)
from app.trees.schemas import InsertionOrder, TreeBuildCreate


class TreeNotFound(LookupError):
    pass


class TreeDatasetNotFound(LookupError):
    pass


class DatasetNotReady(ValueError):
    pass


class InsufficientDatasetKeys(ValueError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class GeneratedTreeService:
    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        payload: TreeBuildCreate,
        dataset: EthereumDataset,
        job: Job,
    ) -> GeneratedTree:
        available = dataset.imported_account_count
        requested = payload.key_count or available
        tree = GeneratedTree(
            name=payload.name,
            dataset_id=dataset.id,
            job_id=job.id,
            tree_type=payload.tree_type,
            hash_function=payload.hash_function,
            width=payload.width,
            requested_key_count=requested,
            status=TreeStatus.QUEUED,
            configuration=payload.model_dump(mode="json"),
        )
        self.session.add(tree)
        self.session.commit()
        self.session.refresh(tree)
        return tree

    def get(self, tree_id: str) -> GeneratedTree:
        tree = self.session.get(GeneratedTree, tree_id)
        if tree is None:
            raise TreeNotFound(tree_id)
        return tree

    def list(self, *, limit: int = 50) -> list[GeneratedTree]:
        statement = (
            select(GeneratedTree).order_by(GeneratedTree.created_at.desc()).limit(limit)
        )
        return list(self.session.scalars(statement))


def validate_dataset(
    session: Session,
    payload: TreeBuildCreate,
) -> EthereumDataset:
    dataset = session.get(EthereumDataset, payload.dataset_id)
    if dataset is None:
        raise TreeDatasetNotFound(payload.dataset_id)
    if dataset.status != DatasetStatus.READY:
        raise DatasetNotReady("Only ready Ethereum datasets can generate trees")
    if dataset.imported_account_count < 1:
        raise InsufficientDatasetKeys("The dataset does not contain any accounts")
    if (
        payload.key_count is not None
        and payload.key_count > dataset.imported_account_count
    ):
        raise InsufficientDatasetKeys(
            f"Requested {payload.key_count} keys, but the dataset contains "
            f"{dataset.imported_account_count}"
        )
    return dataset


def create_tree_records(
    *,
    session: Session,
    artifacts: ArtifactStore,
    payload: TreeBuildCreate,
) -> tuple[GeneratedTree, Job]:
    dataset = validate_dataset(session, payload)
    job = JobService(session).create(
        JobCreate(
            kind=JobKind.TREE_GENERATION,
            parameters=payload.model_dump(mode="json"),
            message="Tree generation queued",
        )
    )
    tree = GeneratedTreeService(session).create(payload, dataset, job)
    artifacts.initialize_job(
        job.id,
        {
            "job_id": job.id,
            "tree_id": tree.id,
            "dataset_id": dataset.id,
            "kind": job.kind.value,
            "status": job.status.value,
            "parameters": job.parameters,
            "created_at": job.created_at,
        },
    )
    workspace = artifacts.path_for("trees", tree.id, create=True)
    artifacts.write_json(
        workspace / "request.json",
        {
            "schema_version": 1,
            "tree_id": tree.id,
            "job_id": job.id,
            "dataset_id": dataset.id,
            "dataset_block": dataset.block_number,
            "dataset_state_root": dataset.state_root,
            "request": payload.model_dump(mode="json"),
            "created_at": tree.created_at,
        },
    )
    return tree, job


def schedule_tree_build(
    application: FastAPI,
    tree_id: str,
) -> asyncio.Task:
    configured_secret = application.state.settings.tree_setup_secret
    tree_setup_secret = (
        int(configured_secret.get_secret_value())
        if configured_secret is not None
        else None
    )
    task = asyncio.create_task(
        run_tree_build(
            database=application.state.database,
            artifacts=application.state.artifacts,
            tree_id=tree_id,
            tree_setup_secret=tree_setup_secret,
        ),
        name=f"tree-build-{tree_id}",
    )
    application.state.background_tasks.add(task)
    task.add_done_callback(application.state.background_tasks.discard)
    return task


def _job_manifest(
    artifacts: ArtifactStore,
    job: Job,
    tree: GeneratedTree,
) -> None:
    workspace = artifacts.path_for("jobs", job.id)
    artifacts.write_json(
        workspace / "manifest.json",
        {
            "job_id": job.id,
            "tree_id": tree.id,
            "dataset_id": tree.dataset_id,
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


def _account_payloads(
    session: Session,
    tree: GeneratedTree,
) -> list[dict[str, str]]:
    statement = (
        select(EthereumAccount)
        .where(EthereumAccount.dataset_id == tree.dataset_id)
        .order_by(EthereumAccount.created_at.asc())
    )
    accounts = list(session.scalars(statement))
    order = tree.configuration.get("insertion_order")
    if order == InsertionOrder.SECURE_KEY.value:
        accounts.sort(key=lambda account: account.secure_trie_key)
    accounts = accounts[: tree.requested_key_count]
    return [
        {
            "address": account.address,
            "secure_trie_key": account.secure_trie_key,
            "account_rlp": account.account_rlp,
        }
        for account in accounts
    ]


async def run_tree_build(
    *,
    database: Database,
    artifacts: ArtifactStore,
    tree_id: str,
    tree_setup_secret: int | None,
) -> None:
    with database.session() as session:
        trees = GeneratedTreeService(session)
        jobs = JobService(session)
        tree = trees.get(tree_id)
        job = jobs.get(tree.job_id)
        dataset = session.get(EthereumDataset, tree.dataset_id)

        try:
            if dataset is None or dataset.status != DatasetStatus.READY:
                raise DatasetNotReady("The source dataset is no longer ready")

            tree.status = TreeStatus.BUILDING
            session.commit()
            job = jobs.update(
                job.id,
                JobUpdate(
                    status=JobStatus.RUNNING,
                    progress=10,
                    message="Preparing secure account keys",
                ),
            )
            accounts = _account_payloads(session, tree)
            if not accounts:
                raise InsufficientDatasetKeys(
                    "The source dataset does not contain accounts"
                )

            workspace = artifacts.path_for("trees", tree.id)
            storage = artifacts.path_for(
                "trees",
                tree.id,
                "storage",
                create=True,
            )
            job = jobs.update(
                job.id,
                JobUpdate(
                    status=JobStatus.RUNNING,
                    progress=25,
                    message=(
                        f"Building {tree.tree_type.value} from "
                        f"{len(accounts)} keys"
                    ),
                ),
            )
            started = perf_counter()
            output: TreeBuildOutput
            if tree.tree_type.value == "merkle_patricia":
                output = build_merkle_patricia_tree(
                    tree_id=tree.id,
                    storage_directory=storage,
                    accounts=accounts,
                    width=tree.width,
                )
            elif tree.tree_type.value == "poseidon_merkle":
                output = build_poseidon_merkle_patricia_tree(
                    tree_id=tree.id,
                    storage_directory=storage,
                    accounts=accounts,
                    width=tree.width,
                )
            elif tree.tree_type.value == "verkle":
                if tree_setup_secret is None:
                    raise ValueError(
                        "STATELESS_TREE_SETUP_SECRET is required for "
                        "Verkle builds"
                    )
                output = build_verkle_tree(
                    tree_id=tree.id,
                    storage_directory=storage,
                    accounts=accounts,
                    width=tree.width,
                    secret=tree_setup_secret,
                )
            else:
                raise ValueError(f"Unsupported tree type: {tree.tree_type.value}")
            duration_ms = round((perf_counter() - started) * 1000)

            root_hash = output.root_hash
            visualization = output.visualization
            persisted_node_count = output.persisted_node_count
            visualization_path = workspace / "visualization.json"
            artifacts.write_json(visualization_path, visualization)
            manifest_path = workspace / "manifest.json"
            metrics = visualization["metrics"]
            artifacts.write_json(
                manifest_path,
                {
                    "schema_version": 1,
                    "tree_id": tree.id,
                    "name": tree.name,
                    "dataset": {
                        "id": dataset.id,
                        "name": dataset.name,
                        "block_number": dataset.block_number,
                        "block_hash": dataset.block_hash,
                        "canonical_state_root": dataset.state_root,
                    },
                    "configuration": {
                        key: value
                        for key, value in tree.configuration.items()
                        if key != "secret"
                    },
                    "tree": {
                        "type": tree.tree_type.value,
                        "hash_function": tree.hash_function.value,
                        "width": tree.width,
                        "root_hash": root_hash,
                        "key_count": len(accounts),
                        **metrics,
                        "persisted_leveldb_nodes": persisted_node_count,
                        "storage_engine": output.storage_engine,
                        "build_duration_ms": duration_ms,
                        **output.extra_manifest,
                    },
                    "files": {
                        "leveldb": str(
                            (
                                storage / output.leveldb_directory
                            ).relative_to(artifacts.root)
                        ),
                        "root": str((storage / "root.bin").relative_to(artifacts.root)),
                        "visualization": str(
                            visualization_path.relative_to(artifacts.root)
                        ),
                    },
                    "root_scope_note": (
                        "This experimental root covers only the selected sampled "
                        "accounts and is not Ethereum's canonical state root."
                    ),
                    "completed_at": utc_now(),
                },
            )

            tree.key_count = len(accounts)
            tree.node_count = metrics["node_count"]
            tree.leaf_count = metrics["leaf_count"]
            tree.extension_count = metrics["extension_count"]
            tree.branch_count = metrics["branch_count"]
            tree.max_depth = metrics["max_depth"]
            tree.root_hash = root_hash
            tree.build_duration_ms = duration_ms
            tree.status = TreeStatus.READY
            tree.artifact_path = str(manifest_path.relative_to(artifacts.root))
            tree.storage_path = str(storage.relative_to(artifacts.root))
            tree.completed_at = utc_now()
            session.commit()
            job = jobs.update(
                job.id,
                JobUpdate(
                    status=JobStatus.SUCCEEDED,
                    progress=100,
                    message=(
                        f"Built {tree.node_count} live "
                        f"{tree.tree_type.value} nodes"
                    ),
                    result={
                        "tree_id": tree.id,
                        "dataset_id": dataset.id,
                        "root_hash": tree.root_hash,
                        "key_count": tree.key_count,
                        "node_count": tree.node_count,
                        "artifact_path": tree.artifact_path,
                    },
                ),
            )
            _job_manifest(artifacts, job, tree)
        except asyncio.CancelledError:
            message = "Tree generation stopped during application shutdown"
            tree.status = TreeStatus.FAILED
            tree.error = message
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
            _job_manifest(artifacts, job, tree)
            raise
        except Exception as exc:
            message = str(exc) or type(exc).__name__
            tree.status = TreeStatus.FAILED
            tree.error = message
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
                        message="Tree generation failed",
                        error=message,
                    ),
                )
            _job_manifest(artifacts, job, tree)
