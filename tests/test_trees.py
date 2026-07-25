import asyncio
from datetime import datetime, timezone
from pathlib import Path

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
from app.schemas import JobCreate
from app.services.jobs import JobService

pytestmark = pytest.mark.anyio

CANONICAL_STATE_ROOT = f"0x{'99' * 32}"


def account_value(seed: int) -> str:
    value = rlp.encode(
        [
            seed,
            seed * 10**18,
            bytes([seed]) * 32,
            bytes([seed + 16]) * 32,
        ]
    )
    return f"0x{value.hex()}"


def seed_ready_dataset(client: httpx2.AsyncClient) -> str:
    with client.application.state.database.session() as session:
        job = JobService(session).create(
            JobCreate(kind=JobKind.ETHEREUM_IMPORT, message="Fixture import")
        )
        dataset = EthereumDataset(
            name="Tree fixture dataset",
            network="mainnet",
            chain_id=1,
            rpc_provider="https://rpc.example.test",
            requested_block="22500000",
            block_number=22_500_000,
            block_hash=f"0x{'88' * 32}",
            state_root=CANONICAL_STATE_ROOT,
            block_timestamp=datetime(2026, 7, 25, tzinfo=timezone.utc),
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

        keys = [
            "f1" + "00" * 31,
            "10" + "11" * 31,
            "f2" + "22" * 31,
            "20" + "33" * 31,
        ]
        for seed, key in enumerate(keys, start=1):
            session.add(
                EthereumAccount(
                    dataset_id=dataset.id,
                    address=f"0x{seed:040x}",
                    secure_trie_key=f"0x{key}",
                    account_rlp=account_value(seed),
                    nonce=str(seed),
                    balance=str(seed * 10**18),
                    storage_root=f"0x{seed:02x}" * 32,
                    code_hash=f"0x{seed + 16:02x}" * 32,
                    account_proof=["0xf8"],
                    proof_node_count=1,
                )
            )
        session.commit()
        return dataset.id


async def wait_for_tree(client: httpx2.AsyncClient, tree_id: str) -> dict:
    for _attempt in range(100):
        response = await client.get(f"/api/v1/trees/{tree_id}")
        tree = response.json()
        if tree["status"] in {"ready", "failed"}:
            return tree
        await asyncio.sleep(0.02)
    raise AssertionError("Tree build did not reach a terminal state")


async def build_tree(
    client: httpx2.AsyncClient,
    dataset_id: str,
    insertion_order: str,
) -> dict:
    response = await client.post(
        "/api/v1/trees/builds",
        json={
            "name": f"Fixture {insertion_order}",
            "dataset_id": dataset_id,
            "insertion_order": insertion_order,
        },
    )
    assert response.status_code == 202
    return await wait_for_tree(client, response.json()["tree"]["id"])


async def test_tree_build_persists_leveldb_metrics_and_visualization(
    client: httpx2.AsyncClient,
) -> None:
    dataset_id = seed_ready_dataset(client)
    tree = await build_tree(client, dataset_id, "secure_key")

    assert tree["status"] == "ready", tree["error"]
    assert tree["key_count"] == 4
    assert tree["leaf_count"] == 4
    assert tree["branch_count"] >= 1
    assert tree["node_count"] == (
        tree["leaf_count"] + tree["extension_count"] + tree["branch_count"]
    )
    assert tree["root_hash"].startswith("0x")
    assert tree["root_hash"] != CANONICAL_STATE_ROOT

    artifact_root: Path = client.application.state.artifacts.root
    storage = artifact_root / tree["storage_path"]
    assert (storage / "merkle_state_db" / "CURRENT").is_file()
    assert (storage / "root.bin").read_bytes().hex() == tree["root_hash"][2:]
    assert (artifact_root / tree["artifact_path"]).is_file()

    visualization_response = await client.get(
        f"/api/v1/trees/{tree['id']}/visualization"
    )
    assert visualization_response.status_code == 200
    visualization = visualization_response.json()
    assert visualization["root_id"] == tree["root_hash"]
    assert len(visualization["nodes"]) == tree["node_count"]
    assert len(visualization["insertion_events"]) == 4
    assert all(event["path"] for event in visualization["insertion_events"])

    job = (await client.get(f"/api/v1/jobs/{tree['job_id']}")).json()
    assert job["status"] == "succeeded"
    assert job["result"]["root_hash"] == tree["root_hash"]

    detail = await client.get(f"/trees/{tree['id']}")
    assert detail.status_code == 200
    assert "Animated topology" in detail.text
    assert tree["root_hash"] in detail.text


async def test_mpt_root_is_independent_of_visual_insertion_order(
    client: httpx2.AsyncClient,
) -> None:
    dataset_id = seed_ready_dataset(client)
    sorted_tree = await build_tree(client, dataset_id, "secure_key")
    imported_tree = await build_tree(client, dataset_id, "dataset")

    assert sorted_tree["status"] == "ready", sorted_tree["error"]
    assert imported_tree["status"] == "ready", imported_tree["error"]
    assert sorted_tree["root_hash"] == imported_tree["root_hash"]


@pytest.mark.parametrize("width", [4, 128])
async def test_generalized_mpt_accepts_boundary_widths(
    client: httpx2.AsyncClient,
    width: int,
) -> None:
    dataset_id = seed_ready_dataset(client)
    response = await client.post(
        "/api/v1/trees/builds",
        json={
            "name": f"Radix {width} MPT",
            "dataset_id": dataset_id,
            "width": width,
            "key_count": 2,
        },
    )
    assert response.status_code == 202, response.text
    tree = await wait_for_tree(client, response.json()["tree"]["id"])
    assert tree["status"] == "ready", tree["error"]
    assert tree["width"] == width

    manifest = client.application.state.artifacts.read_json(
        client.application.state.artifacts.root / tree["artifact_path"]
    )
    assert manifest["tree"]["ethereum_compatible"] is (width == 16)
    assert f"base-{width}" in manifest["tree"]["key_encoding"]


async def test_poseidon_mpt_uses_configured_architecture_profile(
    client: httpx2.AsyncClient,
) -> None:
    dataset_id = seed_ready_dataset(client)
    response = await client.post(
        "/api/v1/trees/builds",
        json={
            "name": "Poseidon fixture",
            "dataset_id": dataset_id,
            "tree_type": "poseidon_merkle",
            "hash_function": "poseidon",
            "setup_type": "",
            "key_length": 32,
            "width": 7,
            "key_count": 3,
        },
    )
    assert response.status_code == 202, response.text
    tree = await wait_for_tree(client, response.json()["tree"]["id"])

    assert tree["status"] == "ready", tree["error"]
    assert tree["tree_type"] == "poseidon_merkle"
    assert tree["hash_function"] == "poseidon"
    assert tree["width"] == 7
    assert tree["key_count"] == 3
    assert tree["root_hash"].startswith("0x")

    artifact_root: Path = client.application.state.artifacts.root
    storage = artifact_root / tree["storage_path"]
    assert (storage / "merkle_state_db" / "CURRENT").is_file()
    manifest = client.application.state.artifacts.read_json(
        artifact_root / tree["artifact_path"]
    )
    assert manifest["tree"]["poseidon_parameters"]["field"] == (
        "BN254 scalar field"
    )


async def test_kzg_verkle_build_persists_setup_and_routes(
    client: httpx2.AsyncClient,
) -> None:
    dataset_id = seed_ready_dataset(client)
    response = await client.post(
        "/api/v1/trees/builds",
        json={
            "name": "Verkle fixture",
            "dataset_id": dataset_id,
            "tree_type": "verkle",
            "hash_function": "kzg",
            "setup_type": "verkle_kzg",
            "key_length": 32,
            "width": 16,
            "key_count": 2,
        },
    )
    assert response.status_code == 202, response.text
    tree = await wait_for_tree(client, response.json()["tree"]["id"])

    assert tree["status"] == "ready", tree["error"]
    assert tree["tree_type"] == "verkle"
    assert tree["hash_function"] == "kzg"
    assert tree["width"] == 16
    assert tree["key_count"] == 2
    assert tree["max_depth"] == 63
    assert "secret" not in tree["configuration"]

    artifact_root: Path = client.application.state.artifacts.root
    storage = artifact_root / tree["storage_path"]
    assert (storage / "verkle_state_db" / "CURRENT").is_file()
    manifest = client.application.state.artifacts.read_json(
        artifact_root / tree["artifact_path"]
    )
    assert manifest["tree"]["setup"] == {
        "type": "verkle_kzg",
        "curve": "BLS12-381",
        "width": 16,
        "secret_source": "server environment",
    }
    assert "123456789" not in response.text
    request_artifact = client.application.state.artifacts.read_json(
        artifact_root / "trees" / tree["id"] / "request.json"
    )
    assert "secret" not in request_artifact["request"]
    assert "123456789" not in str(manifest)
    visualization = (
        await client.get(f"/api/v1/trees/{tree['id']}/visualization")
    ).json()
    assert {node["type"] for node in visualization["nodes"]} == {
        "internal",
        "suffix",
    }
    assert all(event["path"] for event in visualization["insertion_events"])


async def test_tree_build_rejects_more_keys_than_dataset(
    client: httpx2.AsyncClient,
) -> None:
    dataset_id = seed_ready_dataset(client)
    response = await client.post(
        "/api/v1/trees/builds",
        json={
            "name": "Too many keys",
            "dataset_id": dataset_id,
            "key_count": 5,
        },
    )
    assert response.status_code == 409
    assert "contains 4" in response.json()["detail"]


async def test_tree_profile_validation_rejects_invalid_combinations(
    client: httpx2.AsyncClient,
) -> None:
    dataset_id = seed_ready_dataset(client)
    response = await client.post(
        "/api/v1/trees/builds",
        json={
            "name": "Invalid width",
            "dataset_id": dataset_id,
            "tree_type": "poseidon_merkle",
            "hash_function": "poseidon",
            "width": 3,
        },
    )
    assert response.status_code == 422
    assert "between 4 and 128" in response.text

    response = await client.post(
        "/api/v1/trees/builds",
        json={
            "name": "Client secret",
            "dataset_id": dataset_id,
            "secret": "123456789",
        },
    )
    assert response.status_code == 422
    assert "Extra inputs are not permitted" in response.text

    page = await client.get(f"/trees?dataset={dataset_id}")
    assert page.status_code == 200
    assert "Poseidon Merkle Patricia Trie" in page.text
    assert "Verkle Tree (KZG)" in page.text
    assert "MPT accepts radix widths 4–128" in page.text
    assert "123456789" not in page.text
