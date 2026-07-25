import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx2
import pytest
from eth_utils import keccak
from web3 import Web3

from app.config import Settings
from app.ethereum.rpc import AccountProof, PinnedBlock
from app.main import create_app

pytestmark = pytest.mark.anyio

ADDRESS_ONE = "0x0000000000000000000000000000000000000001"
ADDRESS_TWO = "0x0000000000000000000000000000000000000002"
BLOCK_NUMBER = 22_500_000
BLOCK_HASH = f"0x{'ab' * 32}"
STATE_ROOT = f"0x{'cd' * 32}"


class FakeEthereumRPC:
    def __init__(self, chain_id: int = 1):
        self.configured_chain_id = chain_id
        self.proof_blocks: list[int] = []
        self.discovery_calls: list[dict] = []
        self.closed = False

    async def chain_id(self) -> int:
        return self.configured_chain_id

    async def pin_block(self, identifier: str | int) -> PinnedBlock:
        assert identifier in {"latest", "safe", "finalized", BLOCK_NUMBER}
        return PinnedBlock(
            number=BLOCK_NUMBER,
            hash=BLOCK_HASH,
            state_root=STATE_ROOT,
            timestamp=datetime(2026, 7, 25, tzinfo=timezone.utc),
        )

    async def discover_recent_addresses(
        self,
        *,
        block_number: int,
        account_count: int,
        scan_depth: int,
    ) -> list[str]:
        self.discovery_calls.append(
            {
                "block_number": block_number,
                "account_count": account_count,
                "scan_depth": scan_depth,
            }
        )
        discovered = [
            self.normalize_address(ADDRESS_ONE),
            self.normalize_address(ADDRESS_TWO),
        ]
        return discovered[:account_count]

    async def get_account_proof(
        self,
        address: str,
        block_number: int,
    ) -> AccountProof:
        self.proof_blocks.append(block_number)
        suffix = int(address[-1], 16)
        return AccountProof(
            address=self.normalize_address(address),
            nonce=suffix,
            balance=10**18 * suffix,
            storage_root="0x" + f"{suffix:02x}" * 32,
            code_hash="0x" + f"{(suffix + 16):02x}" * 32,
            account_proof=[f"0xf8{suffix:02x}", f"0xe1{suffix:02x}"],
        )

    def normalize_address(self, address: str) -> str:
        return Web3.to_checksum_address(address)

    async def close(self) -> None:
        self.closed = True


class FakeRPCFactory:
    def __init__(self, chain_id: int = 1):
        self.chain_id = chain_id
        self.instances: list[FakeEthereumRPC] = []

    def __call__(self, _settings: Settings) -> FakeEthereumRPC:
        instance = FakeEthereumRPC(chain_id=self.chain_id)
        self.instances.append(instance)
        return instance


@pytest.fixture
async def ethereum_client(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'ethereum.db'}",
        artifact_root=tmp_path / "artifacts",
        auto_migrate=True,
        ethereum_rpc_url="https://rpc.example.test/secret-key",
        ethereum_min_request_interval_seconds=0,
    )
    factory = FakeRPCFactory()
    application = create_app(settings, ethereum_rpc_factory=factory)
    async with application.router.lifespan_context(application):
        transport = httpx2.ASGITransport(app=application)
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            client.application = application
            client.rpc_factory = factory
            yield client


async def wait_for_dataset(
    client: httpx2.AsyncClient,
    dataset_id: str,
) -> dict:
    for _attempt in range(100):
        response = await client.get(f"/api/v1/ethereum/datasets/{dataset_id}")
        dataset = response.json()
        if dataset["status"] in {"ready", "failed"}:
            return dataset
        await asyncio.sleep(0.01)
    raise AssertionError("Ethereum import did not reach a terminal state")


async def test_explicit_import_pins_and_persists_real_state_shape(
    ethereum_client: httpx2.AsyncClient,
) -> None:
    response = await ethereum_client.post(
        "/api/v1/ethereum/imports",
        json={
            "name": "Pinned explicit accounts",
            "block": "latest",
            "address_source": "explicit",
            "addresses": [ADDRESS_ONE, ADDRESS_TWO],
            "account_count": 99,
            "scan_depth": 12,
        },
    )

    assert response.status_code == 202
    accepted = response.json()
    dataset = await wait_for_dataset(
        ethereum_client,
        accepted["dataset"]["id"],
    )

    assert dataset["status"] == "ready"
    assert dataset["block_number"] == BLOCK_NUMBER
    assert dataset["block_hash"] == BLOCK_HASH
    assert dataset["state_root"] == STATE_ROOT
    assert dataset["requested_account_count"] == 2
    assert dataset["imported_account_count"] == 2
    assert dataset["rpc_provider"] == "https://rpc.example.test"

    accounts_response = await ethereum_client.get(
        f"/api/v1/ethereum/datasets/{dataset['id']}/accounts"
    )
    accounts = accounts_response.json()
    assert len(accounts) == 2
    assert accounts[0]["secure_trie_key"] == (
        f"0x{keccak(bytes.fromhex(ADDRESS_ONE[2:])).hex()}"
    )
    assert accounts[0]["account_rlp"].startswith("0x")
    assert accounts[0]["proof_node_count"] == 2

    job = (await ethereum_client.get(f"/api/v1/jobs/{dataset['job_id']}")).json()
    assert job["status"] == "succeeded"
    assert job["result"]["dataset_id"] == dataset["id"]

    snapshot_path = (
        ethereum_client.application.state.artifacts.root / dataset["artifact_path"]
    )
    snapshot = json.loads(snapshot_path.read_text())
    assert snapshot["block"]["hash"] == BLOCK_HASH
    assert len(snapshot["trie_kv"]) == 2
    assert "partial sample" in snapshot["root_scope_note"]

    rpc = ethereum_client.rpc_factory.instances[0]
    assert rpc.proof_blocks == [BLOCK_NUMBER, BLOCK_NUMBER]
    assert rpc.closed is True


async def test_recent_transaction_source_uses_pinned_block(
    ethereum_client: httpx2.AsyncClient,
) -> None:
    response = await ethereum_client.post(
        "/api/v1/ethereum/imports",
        json={
            "name": "Recent participants",
            "block": "safe",
            "address_source": "recent_transactions",
            "account_count": 1,
            "scan_depth": 8,
        },
    )
    dataset = await wait_for_dataset(
        ethereum_client,
        response.json()["dataset"]["id"],
    )

    assert dataset["status"] == "ready"
    rpc = ethereum_client.rpc_factory.instances[-1]
    assert rpc.discovery_calls == [
        {
            "block_number": BLOCK_NUMBER,
            "account_count": 1,
            "scan_depth": 8,
        }
    ]
    assert rpc.proof_blocks == [BLOCK_NUMBER]


async def test_chain_mismatch_is_persisted_as_failed_dataset(
    tmp_path: Path,
) -> None:
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'mismatch.db'}",
        artifact_root=tmp_path / "artifacts",
        auto_migrate=True,
        ethereum_rpc_url="https://rpc.example.test/key",
        ethereum_expected_chain_id=1,
    )
    factory = FakeRPCFactory(chain_id=11155111)
    application = create_app(settings, ethereum_rpc_factory=factory)

    async with application.router.lifespan_context(application):
        transport = httpx2.ASGITransport(app=application)
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            response = await client.post(
                "/api/v1/ethereum/imports",
                json={
                    "name": "Wrong chain",
                    "address_source": "explicit",
                    "addresses": [ADDRESS_ONE],
                },
            )
            dataset = await wait_for_dataset(
                client,
                response.json()["dataset"]["id"],
            )

            assert dataset["status"] == "failed"
            assert "Expected chain ID 1" in dataset["error"]
            job = (await client.get(f"/api/v1/jobs/{dataset['job_id']}")).json()
            assert job["status"] == "failed"


async def test_import_requires_server_side_rpc_configuration(
    client: httpx2.AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/ethereum/imports",
        json={
            "name": "No RPC",
            "address_source": "explicit",
            "addresses": [ADDRESS_ONE],
        },
    )
    assert response.status_code == 503


async def test_data_pages_explain_root_scope(
    ethereum_client: httpx2.AsyncClient,
) -> None:
    page = await ethereum_client.get("/data")
    assert page.status_code == 200
    assert "Pin the chain" in page.text
    assert "experimental root" in page.text
    assert "secret-key" not in page.text
