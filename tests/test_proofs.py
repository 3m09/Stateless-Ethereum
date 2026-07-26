import asyncio
import csv
from datetime import datetime, timezone

import httpx2
import pytest
import rlp

from app.models import (
    AddressSource,
    DatasetStatus,
    EthereumAccount,
    EthereumDataset,
    JobKind,
)
from app.proofs.service import RESULT_COLUMNS
from app.schemas import JobCreate
from app.services.jobs import JobService

pytestmark = pytest.mark.anyio


def _account_value(seed: int) -> str:
    encoded = rlp.encode(
        [
            seed,
            seed * 10**18,
            bytes([seed]) * 32,
            bytes([seed + 16]) * 32,
        ]
    )
    return f"0x{encoded.hex()}"


def _seed_dataset(client: httpx2.AsyncClient) -> str:
    with client.application.state.database.session() as session:
        job = JobService(session).create(
            JobCreate(kind=JobKind.ETHEREUM_IMPORT, message="Proof fixture import")
        )
        dataset = EthereumDataset(
            name="Proof fixture dataset",
            network="mainnet",
            chain_id=1,
            rpc_provider="https://rpc.example.test",
            requested_block="22500000",
            block_number=22_500_000,
            block_hash=f"0x{'88' * 32}",
            state_root=f"0x{'99' * 32}",
            block_timestamp=datetime(2026, 7, 26, tzinfo=timezone.utc),
            address_source=AddressSource.EXPLICIT,
            requested_account_count=4,
            imported_account_count=4,
            scan_depth=1,
            status=DatasetStatus.READY,
            job_id=job.id,
            fetched_at=datetime.now(timezone.utc),
        )
        session.add(dataset)
        session.flush()
        for seed, prefix in enumerate(("10", "44", "88", "f0"), start=1):
            session.add(
                EthereumAccount(
                    dataset_id=dataset.id,
                    address=f"0x{seed:040x}",
                    secure_trie_key=f"0x{prefix}{seed:02x}{'00' * 30}",
                    account_rlp=_account_value(seed),
                    nonce=str(seed),
                    balance=str(seed * 10**18),
                    storage_root=f"0x{seed:064x}",
                    code_hash=f"0x{seed + 16:064x}",
                    account_proof=["0xf8"],
                    proof_node_count=1,
                )
            )
        session.commit()
        return dataset.id


async def _wait_for(
    client: httpx2.AsyncClient,
    endpoint: str,
    statuses: set[str],
) -> dict:
    for _attempt in range(300):
        response = await client.get(endpoint)
        assert response.status_code == 200
        payload = response.json()
        if payload["status"] in statuses:
            return payload
        await asyncio.sleep(0.02)
    raise AssertionError(f"{endpoint} did not reach a terminal state")


async def _build_tree(
    client: httpx2.AsyncClient,
    *,
    tree_type: str = "merkle_patricia",
    hash_function: str = "keccak",
    setup_type: str = "",
    width: int = 16,
) -> dict:
    response = await client.post(
        "/api/v1/trees/builds",
        json={
            "name": f"Proof source {tree_type} {width}",
            "dataset_id": _seed_dataset(client),
            "tree_type": tree_type,
            "hash_function": hash_function,
            "setup_type": setup_type,
            "width": width,
            "key_count": 4,
        },
    )
    assert response.status_code == 202, response.text
    tree_id = response.json()["tree"]["id"]
    return await _wait_for(
        client,
        f"/api/v1/trees/{tree_id}",
        {"ready", "failed"},
    )


@pytest.mark.parametrize(
    ("width", "prover_type"),
    [(4, "merkle"), (128, "merkle_optimized")],
)
async def test_mpt_proof_experiment_supports_configured_radix_and_csv(
    client: httpx2.AsyncClient,
    width: int,
    prover_type: str,
) -> None:
    tree = await _build_tree(client, width=width)
    assert tree["status"] == "ready", tree["error"]

    response = await client.post(
        "/api/v1/proofs/experiments",
        json={
            "name": f"Radix {width} benchmark",
            "tree_id": tree["id"],
            "prover_type": prover_type,
            "verifier_type": prover_type,
            "setup_type": "",
            "num_keys_to_prove": 3,
            "selection_seed": 17,
        },
    )
    assert response.status_code == 202, response.text
    experiment_id = response.json()["experiment"]["id"]
    result = await _wait_for(
        client,
        f"/api/v1/proofs/experiments/{experiment_id}",
        {"ready", "failed"},
    )

    assert result["status"] == "ready", result["error"]
    assert result["verified"] is True
    assert result["width"] == width
    assert result["proof_size"] > 0
    assert result["proving_time"] >= 0
    assert result["verification_time"] >= 0
    assert len(result["sampled_keys"]) == 3

    workspace = client.application.state.artifacts.path_for(
        "proofs",
        experiment_id,
    )
    assert (workspace / "request.json").is_file()
    assert (workspace / "result.json").is_file()
    assert (workspace / "sampled_keys.json").is_file()
    with (workspace / "result.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert tuple(rows[0]) == RESULT_COLUMNS
    assert rows[0]["NUM_KEYS_TO_PROVE"] == "3"
    assert rows[0]["NUM_KEYS_TREE"] == "4"

    page = await client.get(f"/proofs/{experiment_id}")
    assert page.status_code == 200
    assert "Proof accepted" in page.text
    pending = list(client.application.state.background_tasks)
    if pending:
        await asyncio.wait_for(asyncio.gather(*pending), timeout=2)


async def test_verkle_experiment_resolves_kzg_setup_and_verifies(
    client: httpx2.AsyncClient,
) -> None:
    tree = await _build_tree(
        client,
        tree_type="verkle",
        hash_function="kzg",
        setup_type="verkle_kzg",
        width=16,
    )
    assert tree["status"] == "ready", tree["error"]

    response = await client.post(
        "/api/v1/proofs/experiments",
        json={
            "name": "KZG multiproof benchmark",
            "tree_id": tree["id"],
            "prover_type": "verkle_multiproof_optimized",
            "verifier_type": "verkle_multiproof_optimized",
            "setup_type": "verkle_kzg",
            "num_keys_to_prove": 1,
            "selection_seed": 3,
        },
    )
    assert response.status_code == 202, response.text
    result = await _wait_for(
        client,
        f"/api/v1/proofs/experiments/{response.json()['experiment']['id']}",
        {"ready", "failed"},
    )
    assert result["status"] == "ready", result["error"]
    assert result["verified"] is True
    assert result["setup_type"] == "verkle_kzg"
    assert result["proof_size"] > 0


async def test_poseidon_tree_rejects_incomplete_legacy_proof_contract(
    client: httpx2.AsyncClient,
) -> None:
    tree = await _build_tree(
        client,
        tree_type="poseidon_merkle",
        hash_function="poseidon",
        width=16,
    )
    assert tree["status"] == "ready", tree["error"]
    response = await client.post(
        "/api/v1/proofs/experiments",
        json={
            "name": "Unsupported Poseidon proof",
            "tree_id": tree["id"],
            "prover_type": "zksnarkmerkle",
            "verifier_type": "zksnarkmerkle",
            "setup_type": "",
            "num_keys_to_prove": 1,
        },
    )
    assert response.status_code == 409
    assert "do not yet share a complete proof contract" in response.json()["detail"]
