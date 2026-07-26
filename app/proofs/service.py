from __future__ import annotations

import asyncio
import csv
import random
import threading
from concurrent.futures import Executor
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.artifacts import ArtifactStore
from app.database import Database
from app.models import (
    EthereumAccount,
    GeneratedTree,
    Job,
    JobKind,
    JobStatus,
    ProofExperiment,
    ProofStatus,
    TreeStatus,
    TreeType,
)
from app.proofs.profiles import ProofProfile, UnsupportedProofProfile, resolve_profile
from app.proofs.schemas import ProofExperimentCreate
from app.schemas import JobCreate, JobUpdate
from app.services.jobs import JobService
from app.trees.engine import _verkle_setup
from app.trees.schemas import InsertionOrder

RESULT_COLUMNS = (
    "datetime",
    "WIDTH",
    "TREE_TYPE",
    "PROVER_TYPE",
    "VERIFIER_TYPE",
    "SETUP_TYPE",
    "NUM_KEYS_TO_PROVE",
    "NUM_KEYS_TREE",
    "proof_size",
    "proving_time",
    "verification_time",
)
_results_csv_lock = threading.Lock()


class ProofExperimentNotFound(LookupError):
    pass


class ProofTreeNotFound(LookupError):
    pass


class ProofTreeNotReady(ValueError):
    pass


class TooManyProofKeys(ValueError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ProofExperimentService:
    def __init__(self, session: Session):
        self.session = session

    def get(self, experiment_id: str) -> ProofExperiment:
        experiment = self.session.get(ProofExperiment, experiment_id)
        if experiment is None:
            raise ProofExperimentNotFound(experiment_id)
        return experiment

    def list(self, *, limit: int = 50) -> list[ProofExperiment]:
        statement = (
            select(ProofExperiment)
            .order_by(ProofExperiment.created_at.desc())
            .limit(limit)
        )
        return list(self.session.scalars(statement))


def validate_experiment(
    session: Session,
    payload: ProofExperimentCreate,
) -> tuple[GeneratedTree, ProofProfile]:
    tree = session.get(GeneratedTree, payload.tree_id)
    if tree is None:
        raise ProofTreeNotFound(payload.tree_id)
    if tree.status != TreeStatus.READY or not tree.storage_path:
        raise ProofTreeNotReady("Only ready, persisted trees can be proved")
    if payload.num_keys_to_prove > tree.key_count:
        raise TooManyProofKeys(
            f"Requested {payload.num_keys_to_prove} keys, but the tree contains "
            f"{tree.key_count}"
        )
    profile = resolve_profile(
        tree,
        prover_type=payload.prover_type,
        verifier_type=payload.verifier_type,
        setup_type=payload.setup_type,
    )
    return tree, profile


def create_experiment_records(
    *,
    session: Session,
    artifacts: ArtifactStore,
    payload: ProofExperimentCreate,
) -> tuple[ProofExperiment, Job]:
    tree, profile = validate_experiment(session, payload)
    public_parameters = payload.model_dump(mode="json")
    job = JobService(session).create(
        JobCreate(
            kind=JobKind.PROOF_EXPERIMENT,
            parameters=public_parameters,
            message="Proof experiment queued",
        )
    )
    experiment = ProofExperiment(
        name=payload.name,
        tree_id=tree.id,
        job_id=job.id,
        prover_type=profile.prover_type,
        verifier_type=profile.verifier_type,
        setup_type=profile.setup_type,
        width=tree.width,
        tree_type=tree.tree_type.value,
        requested_key_count=payload.num_keys_to_prove,
        num_keys_tree=tree.key_count,
        selection_seed=payload.selection_seed,
        status=ProofStatus.QUEUED,
    )
    session.add(experiment)
    session.commit()
    session.refresh(experiment)
    artifacts.initialize_job(
        job.id,
        {
            "job_id": job.id,
            "experiment_id": experiment.id,
            "tree_id": tree.id,
            "kind": job.kind.value,
            "status": job.status.value,
            "parameters": public_parameters,
            "created_at": job.created_at,
        },
    )
    workspace = artifacts.path_for("proofs", experiment.id, create=True)
    artifacts.write_json(
        workspace / "request.json",
        {
            "schema_version": 1,
            "experiment_id": experiment.id,
            "job_id": job.id,
            "tree_id": tree.id,
            "request": public_parameters,
            "resolved_profile": profile.as_dict(),
            "created_at": experiment.created_at,
        },
    )
    return experiment, job


def schedule_proof_experiment(
    application: FastAPI,
    experiment_id: str,
) -> asyncio.Task:
    configured_secret = application.state.settings.tree_setup_secret
    tree_setup_secret = (
        int(configured_secret.get_secret_value())
        if configured_secret is not None
        else None
    )
    task = asyncio.create_task(
        run_proof_experiment(
            database=application.state.database,
            artifacts=application.state.artifacts,
            experiment_id=experiment_id,
            tree_setup_secret=tree_setup_secret,
            executor=application.state.proof_executor,
        ),
        name=f"proof-experiment-{experiment_id}",
    )
    application.state.background_tasks.add(task)
    task.add_done_callback(application.state.background_tasks.discard)
    return task


async def run_proof_experiment(
    *,
    database: Database,
    artifacts: ArtifactStore,
    experiment_id: str,
    tree_setup_secret: int | None,
    executor: Executor,
) -> None:
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        executor,
        _run_proof_experiment_sync,
        database,
        artifacts,
        experiment_id,
        tree_setup_secret,
    )


def _account_rows(session: Session, tree: GeneratedTree) -> list[EthereumAccount]:
    statement = (
        select(EthereumAccount)
        .where(EthereumAccount.dataset_id == tree.dataset_id)
        .order_by(EthereumAccount.created_at.asc())
    )
    accounts = list(session.scalars(statement))
    if tree.configuration.get("insertion_order") == InsertionOrder.SECURE_KEY.value:
        accounts.sort(key=lambda account: account.secure_trie_key)
    return accounts[: tree.key_count]


def _open_tree(
    tree: GeneratedTree,
    artifacts: ArtifactStore,
    tree_setup_secret: int | None,
):
    storage = artifacts.root / str(tree.storage_path)
    if tree.tree_type == TreeType.MERKLE_PATRICIA:
        from tree.merkle_tree import MerklePatriciaTrie

        return MerklePatriciaTrie(
            width=tree.width,
            db_path=str(storage),
            hash_fn="keccak",
        ), None
    if tree.tree_type == TreeType.VERKLE:
        if tree_setup_secret is None:
            raise ValueError(
                "STATELESS_TREE_SETUP_SECRET is required for Verkle proofs"
            )
        from tree.verkle_tree import VerkleTree

        setup = _verkle_setup(tree_setup_secret, tree.width)
        return VerkleTree(
            tree.width,
            db_path=str(storage),
            setup_object=setup,
        ), setup
    raise UnsupportedProofProfile(
        f"No runnable proof implementation for {tree.tree_type.value}"
    )


def _csv_row(
    experiment: ProofExperiment,
    profile: ProofProfile,
) -> dict[str, object]:
    return {
        "datetime": experiment.completed_at.isoformat(),
        "WIDTH": experiment.width,
        "TREE_TYPE": (
            "merkle" if profile.tree_type == TreeType.MERKLE_PATRICIA else "verkle"
        ),
        "PROVER_TYPE": experiment.prover_type,
        "VERIFIER_TYPE": experiment.verifier_type,
        "SETUP_TYPE": experiment.setup_type,
        "NUM_KEYS_TO_PROVE": experiment.requested_key_count,
        "NUM_KEYS_TREE": experiment.num_keys_tree,
        "proof_size": experiment.proof_size,
        "proving_time": experiment.proving_time,
        "verification_time": experiment.verification_time,
    }


def _write_csv(path: Path, row: dict[str, object], *, append: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not append or not path.exists() or path.stat().st_size == 0
    mode = "a" if append else "w"
    with path.open(mode, encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RESULT_COLUMNS)
        if needs_header:
            writer.writeheader()
        writer.writerow(row)


def _write_job_manifest(
    artifacts: ArtifactStore,
    job: Job,
    experiment: ProofExperiment,
) -> None:
    workspace = artifacts.path_for("jobs", job.id)
    artifacts.write_json(
        workspace / "manifest.json",
        {
            "job_id": job.id,
            "experiment_id": experiment.id,
            "tree_id": experiment.tree_id,
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


def _run_proof_experiment_sync(
    database: Database,
    artifacts: ArtifactStore,
    experiment_id: str,
    tree_setup_secret: int | None,
) -> None:
    from registry.provers import PROVER_REGISTRY
    from registry.verifiers import VERIFIER_REGISTRY

    with database.session() as session:
        experiments = ProofExperimentService(session)
        jobs = JobService(session)
        experiment = experiments.get(experiment_id)
        job = jobs.get(experiment.job_id)
        tree_record = session.get(GeneratedTree, experiment.tree_id)
        tree_instance = None
        try:
            if tree_record is None:
                raise ProofTreeNotFound(experiment.tree_id)
            profile = resolve_profile(
                tree_record,
                prover_type=experiment.prover_type,
                verifier_type=experiment.verifier_type,
                setup_type=experiment.setup_type,
            )
            experiment.status = ProofStatus.PROVING
            session.commit()
            job = jobs.update(
                job.id,
                JobUpdate(
                    status=JobStatus.RUNNING,
                    progress=10,
                    message="Selecting deterministic tree keys",
                ),
            )
            accounts = _account_rows(session, tree_record)
            sampled = random.Random(experiment.selection_seed).sample(
                accounts,
                experiment.requested_key_count,
            )
            keys = [
                bytes.fromhex(account.secure_trie_key.removeprefix("0x"))
                for account in sampled
            ]
            values = [
                bytes.fromhex(account.account_rlp.removeprefix("0x"))
                for account in sampled
            ]
            experiment.sampled_keys = [
                {
                    "address": account.address,
                    "secure_trie_key": account.secure_trie_key,
                }
                for account in sampled
            ]
            session.commit()

            tree_instance, setup = _open_tree(
                tree_record,
                artifacts,
                tree_setup_secret,
            )
            job = jobs.update(
                job.id,
                JobUpdate(
                    status=JobStatus.RUNNING,
                    progress=35,
                    message=f"Generating {profile.label}",
                ),
            )
            prover = PROVER_REGISTRY[profile.prover_type](setup)
            started = perf_counter()
            proof = prover.generate_proof(tree_instance, keys)
            proving_time = perf_counter() - started
            proof_size = prover.proof_size(*proof)

            job = jobs.update(
                job.id,
                JobUpdate(
                    status=JobStatus.RUNNING,
                    progress=70,
                    message="Verifying proof against the persisted root",
                ),
            )
            if tree_record.tree_type == TreeType.VERKLE:
                root = tree_instance.root.commitment_to_children
            else:
                root = tree_instance.root_hash()
            verifier = VERIFIER_REGISTRY[profile.verifier_type](setup)
            started = perf_counter()
            verified = bool(verifier.verify_proof(values, keys, root, proof))
            verification_time = perf_counter() - started

            experiment.proof_size = proof_size
            experiment.proving_time = proving_time
            experiment.verification_time = verification_time
            experiment.verified = verified
            experiment.root_hash = tree_record.root_hash
            experiment.completed_at = utc_now()
            workspace = artifacts.path_for("proofs", experiment.id)
            result_path = workspace / "result.json"
            experiment.artifact_path = str(result_path.relative_to(artifacts.root))
            session.commit()

            result = {
                "schema_version": 1,
                "experiment_id": experiment.id,
                "tree_id": experiment.tree_id,
                "profile": profile.as_dict(),
                "parameters": {
                    "width": experiment.width,
                    "num_keys_to_prove": experiment.requested_key_count,
                    "num_keys_tree": experiment.num_keys_tree,
                    "selection_seed": experiment.selection_seed,
                },
                "sampled_keys": experiment.sampled_keys,
                "results": {
                    "verified": experiment.verified,
                    "proof_size": experiment.proof_size,
                    "proving_time": experiment.proving_time,
                    "verification_time": experiment.verification_time,
                    "root_hash": experiment.root_hash,
                },
                "completed_at": experiment.completed_at,
            }
            artifacts.write_json(result_path, result)
            csv_row = _csv_row(experiment, profile)
            _write_csv(workspace / "result.csv", csv_row, append=False)
            with _results_csv_lock:
                _write_csv(
                    artifacts.root / "proofs" / "results.csv",
                    csv_row,
                    append=True,
                )
            artifacts.write_json(
                workspace / "sampled_keys.json",
                {
                    "selection_seed": experiment.selection_seed,
                    "keys": experiment.sampled_keys,
                },
            )
            tree_instance.db.close()
            tree_instance = None
            job = jobs.update(
                job.id,
                JobUpdate(
                    status=JobStatus.SUCCEEDED,
                    progress=100,
                    message=(
                        "Proof verified successfully"
                        if verified
                        else "Proof completed but verification returned false"
                    ),
                    result={
                        "experiment_id": experiment.id,
                        "tree_id": experiment.tree_id,
                        "verified": experiment.verified,
                        "proof_size": experiment.proof_size,
                        "proving_time": experiment.proving_time,
                        "verification_time": experiment.verification_time,
                        "artifact_path": experiment.artifact_path,
                    },
                ),
            )
            _write_job_manifest(artifacts, job, experiment)
            experiment.status = ProofStatus.READY
            session.commit()
        except Exception as exc:
            message = str(exc) or type(exc).__name__
            experiment.status = ProofStatus.FAILED
            experiment.error = message
            experiment.completed_at = utc_now()
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
                        message="Proof experiment failed",
                        error=message,
                    ),
                )
            _write_job_manifest(artifacts, job, experiment)
        finally:
            if tree_instance is not None:
                tree_instance.db.close()
