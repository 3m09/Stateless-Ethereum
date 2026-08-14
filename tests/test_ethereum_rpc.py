import pytest
from web3 import Web3
from web3.exceptions import Web3RPCError

from app.config import Settings
from app.ethereum.rpc import (
    EthereumRPCRequestError,
    Web3EthereumRPC,
    account_proof_state_root,
)

pytestmark = pytest.mark.anyio


def rpc_error(code: int, message: str) -> Web3RPCError:
    return Web3RPCError(
        message,
        rpc_response={
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": code, "message": message},
        },
    )


def rpc_settings() -> Settings:
    return Settings(
        _env_file=None,
        ethereum_rpc_url="https://rpc.example.test/key",
        ethereum_proof_rpc_url="https://proof.example.test",
        ethereum_retry_attempts=3,
        ethereum_retry_backoff_seconds=0,
        ethereum_min_request_interval_seconds=0,
    )


def test_account_proof_state_root_hashes_root_node() -> None:
    root_node = "0xf83fa0" + ("11" * 32) + "a0" + ("22" * 32)

    assert account_proof_state_root([root_node, "0xc0"]) == Web3.to_hex(
        Web3.keccak(bytes.fromhex(root_node.removeprefix("0x")))
    )


async def test_transient_internal_rpc_error_is_retried() -> None:
    rpc = Web3EthereumRPC(rpc_settings())
    attempts = 0

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise rpc_error(-32603, "Internal error")
        return "ok"

    try:
        result = await rpc._request(operation, operation_name="test operation")
    finally:
        await rpc.close()

    assert result == "ok"
    assert attempts == 3


async def test_exhausted_transient_error_has_operation_context() -> None:
    rpc = Web3EthereumRPC(rpc_settings())

    async def operation() -> None:
        raise rpc_error(-32603, "Internal error")

    try:
        with pytest.raises(EthereumRPCRequestError) as caught:
            await rpc._request(operation, operation_name="proof request")
    finally:
        await rpc.close()

    assert str(caught.value) == (
        "proof request failed after 3 attempts (RPC -32603: Internal error)"
    )
