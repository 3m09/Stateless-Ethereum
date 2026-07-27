import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx2
import pytest
import rlp
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
        self.proof_blocks: list[str | int] = []
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
        block_number: str | int,
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
            proof_state_root=STATE_ROOT,
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


class ManyAccountRPC(FakeEthereumRPC):
    def __init__(self):
        super().__init__()
        self.active_proof_requests = 0
        self.max_active_proof_requests = 0

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
        return [
            self.normalize_address(f"0x{index:040x}")
            for index in range(1, account_count + 1)
        ]

    async def get_account_proof(
        self,
        address: str,
        block_number: str | int,
    ) -> AccountProof:
        self.proof_blocks.append(block_number)
        self.active_proof_requests += 1
        self.max_active_proof_requests = max(
            self.max_active_proof_requests,
            self.active_proof_requests,
        )
        try:
            await asyncio.sleep(0.0001)
            seed = ((int(address, 16) - 1) % 255) + 1
            return AccountProof(
                address=self.normalize_address(address),
                nonce=seed,
                balance=10**18 * seed,
                storage_root="0x" + f"{seed:02x}" * 32,
                code_hash="0x" + f"{(seed + 1) % 256:02x}" * 32,
                account_proof=[f"0xf8{seed:02x}"],
                proof_state_root="0x" + f"{seed:02x}" * 32,
            )
        finally:
            self.active_proof_requests -= 1


class ManyAccountRPCFactory:
    def __init__(self):
        self.instances: list[ManyAccountRPC] = []

    def __call__(self, _settings: Settings) -> ManyAccountRPC:
        instance = ManyAccountRPC()
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
    for _attempt in range(500):
        response = await client.get(f"/api/v1/ethereum/datasets/{dataset_id}")
        dataset = response.json()
        if dataset["status"] in {"ready", "failed"}:
            return dataset
        await asyncio.sleep(0.02)
    raise AssertionError("Ethereum import did not reach a terminal state")


async def test_explicit_import_pins_and_persists_real_state_shape(
    ethereum_client: httpx2.AsyncClient,
) -> None:
    response = await ethereum_client.post(
        "/api/v1/ethereum/imports",
        json={
            "name": "Pinned explicit accounts",
            "block": "latest",
            "state_mode": "pinned",
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
            "state_mode": "pinned",
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
            "account_count": 257,
            "scan_depth": 8,
        }
    ]
    assert rpc.proof_blocks == [BLOCK_NUMBER]


async def test_rolling_latest_import_handles_2048_accounts(
    tmp_path: Path,
) -> None:
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'many-accounts.db'}",
        artifact_root=tmp_path / "artifacts",
        auto_migrate=True,
        ethereum_rpc_url="https://rpc.example.test/key",
        ethereum_proof_rpc_url="https://proof.example.test",
        ethereum_proof_concurrency=8,
        ethereum_min_request_interval_seconds=0,
    )
    factory = ManyAccountRPCFactory()
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
                    "name": "2048 account sample",
                    "block": "latest",
                    "state_mode": "rolling_latest",
                    "address_source": "recent_transactions",
                    "account_count": 2048,
                    "scan_depth": 100,
                },
            )
            assert response.status_code == 202
            dataset = await wait_for_dataset(
                client,
                response.json()["dataset"]["id"],
            )

            assert dataset["status"] == "ready", dataset["error"]
            assert dataset["requested_account_count"] == 2048
            assert dataset["imported_account_count"] == 2048
            assert dataset["state_mode"] == "rolling_latest"
            assert dataset["observed_state_root_count"] == 255
            assert dataset["rpc_provider"] == "https://proof.example.test"
            accounts = (
                await client.get(
                    f"/api/v1/ethereum/datasets/{dataset['id']}/accounts?limit=2048"
                )
            ).json()
            assert len(accounts) == 2048
            assert all(account["proof_state_root"] for account in accounts)
            rpc = factory.instances[0]
            assert len(rpc.proof_blocks) == 2048
            assert set(rpc.proof_blocks) == {"latest"}
            assert rpc.max_active_proof_requests == 8
            assert rpc.closed is True


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


async def test_live_import_rejects_non_power_of_two_account_count(
    ethereum_client: httpx2.AsyncClient,
) -> None:
    response = await ethereum_client.post(
        "/api/v1/ethereum/imports",
        json={
            "name": "Invalid sample size",
            "block": "latest",
            "address_source": "recent_transactions",
            "account_count": 3,
        },
    )

    assert response.status_code == 422
    assert "power of two" in response.text


def local_trie_json(count: int) -> bytes:
    payload = {}
    for index in range(1, count + 1):
        secure_key = f"0x{index:064x}"
        account_value = rlp.encode(
            [
                index,
                index * 10**18,
                bytes([index % 256]) * 32,
                bytes([(index + 1) % 256]) * 32,
            ]
        )
        payload[secure_key] = f"0x{account_value.hex()}"
    return json.dumps(payload).encode()


async def test_local_json_import_creates_ready_dataset(
    ethereum_client: httpx2.AsyncClient,
) -> None:
    response = await ethereum_client.post(
        "/api/v1/ethereum/imports/json",
        data={"name": "Uploaded 4-account sample"},
        files={
            "data_file": (
                "ethereum_trie_data.json",
                local_trie_json(4),
                "application/json",
            )
        },
    )

    assert response.status_code == 201, response.text
    accepted = response.json()
    dataset = accepted["dataset"]
    assert dataset["status"] == "ready"
    assert dataset["address_source"] == "local_json"
    assert dataset["state_mode"] == "local_import"
    assert dataset["network"] == "local"
    assert dataset["requested_account_count"] == 4
    assert dataset["imported_account_count"] == 4
    assert dataset["block_number"] is None
    assert dataset["rpc_provider"] == "local-json"

    accounts = (
        await ethereum_client.get(
            f"/api/v1/ethereum/datasets/{dataset['id']}/accounts?limit=4"
        )
    ).json()
    assert len(accounts) == 4
    assert all(account["address"] is None for account in accounts)
    assert all(account["account_proof"] == [] for account in accounts)
    assert all(account["proof_state_root"] is None for account in accounts)

    snapshot_path = (
        ethereum_client.application.state.artifacts.root / dataset["artifact_path"]
    )
    snapshot = json.loads(snapshot_path.read_text())
    assert snapshot["source_file"]["original_filename"] == (
        "ethereum_trie_data.json"
    )
    assert len(snapshot["trie_kv"]) == 4
    assert "not independently authenticated" in snapshot["root_scope_note"]

    job = (await ethereum_client.get(f"/api/v1/jobs/{dataset['job_id']}")).json()
    assert job["status"] == "succeeded"

    tree_response = await ethereum_client.post(
        "/api/v1/trees/builds",
        json={
            "name": "Tree from local JSON",
            "dataset_id": dataset["id"],
            "tree_type": "merkle_patricia",
            "hash_function": "keccak",
            "setup_type": "",
            "key_length": 32,
            "width": 16,
            "key_count": 4,
            "insertion_order": "secure_key",
        },
    )
    assert tree_response.status_code == 202
    tree_id = tree_response.json()["tree"]["id"]
    for _attempt in range(200):
        tree = (await ethereum_client.get(f"/api/v1/trees/{tree_id}")).json()
        if tree["status"] in {"ready", "failed"}:
            break
        await asyncio.sleep(0.02)
    assert tree["status"] == "ready", tree["error"]
    assert tree["key_count"] == 4


async def test_local_json_import_rejects_non_power_of_two_entries(
    ethereum_client: httpx2.AsyncClient,
) -> None:
    response = await ethereum_client.post(
        "/api/v1/ethereum/imports/json",
        data={"name": "Invalid local sample"},
        files={
            "data_file": (
                "three.json",
                local_trie_json(3),
                "application/json",
            )
        },
    )

    assert response.status_code == 422
    assert "power of two" in response.text


async def test_data_pages_explain_root_scope(
    ethereum_client: httpx2.AsyncClient,
) -> None:
    page = await ethereum_client.get("/data")
    assert page.status_code == 200
    assert "Sample the chain" in page.text
    assert "Rolling latest:" in page.text
    assert "Pinned block:" in page.text
    assert "Recent transactions:" in page.text
    assert "Explicit list:" in page.text
    assert "Import trie key/value JSON" in page.text
    assert 'option value="2048"' in page.text
    assert "experimental root" in page.text
    assert "secret-key" not in page.text
