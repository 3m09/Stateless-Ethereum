import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from time import monotonic
from typing import Protocol
from urllib.parse import urlsplit

import aiohttp
from web3 import AsyncHTTPProvider, AsyncWeb3, Web3
from web3.exceptions import Web3RPCError
from web3.types import RPCEndpoint

from app.config import Settings


def as_hex(value: object) -> str:
    if isinstance(value, str):
        return value if value.startswith("0x") else f"0x{value}"
    if isinstance(value, (bytes, bytearray)):
        return f"0x{bytes(value).hex()}"
    hex_method = getattr(value, "hex", None)
    if callable(hex_method):
        result = hex_method()
        return result if result.startswith("0x") else f"0x{result}"
    raise TypeError(f"Cannot encode {type(value).__name__} as hex")


def rpc_provider_label(url: str) -> str:
    """Return provenance that cannot expose credentials embedded in a URL."""

    parsed = urlsplit(url)
    hostname = parsed.hostname or "configured-provider"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{hostname}{port}"


def account_proof_state_root(account_proof: list[str]) -> str:
    """Derive the authenticated state root from an EIP-1186 proof."""

    if not account_proof:
        raise ValueError("eth_getProof returned an empty account proof")
    root_node = bytes.fromhex(account_proof[0].removeprefix("0x"))
    return as_hex(Web3.keccak(root_node))


@dataclass(frozen=True)
class PinnedBlock:
    number: int
    hash: str
    state_root: str
    timestamp: datetime


@dataclass(frozen=True)
class AccountProof:
    address: str
    nonce: int
    balance: int
    storage_root: str
    code_hash: str
    account_proof: list[str]
    proof_state_root: str


class EthereumRPCRequestError(RuntimeError):
    """A provider request that remained unavailable after safe retries."""

    def __init__(
        self,
        *,
        operation_name: str,
        attempts: int,
        provider_error: str,
        rpc_code: int | None = None,
        provider_message: str | None = None,
    ):
        super().__init__(
            f"{operation_name} failed after {attempts} attempts ({provider_error})"
        )
        self.operation_name = operation_name
        self.attempts = attempts
        self.rpc_code = rpc_code
        self.provider_message = provider_message


class EthereumRPC(Protocol):
    async def chain_id(self) -> int: ...

    async def pin_block(self, identifier: str | int) -> PinnedBlock: ...

    async def discover_recent_addresses(
        self,
        *,
        block_number: int,
        account_count: int,
        scan_depth: int,
    ) -> list[str]: ...

    async def get_account_proof(
        self,
        address: str,
        block_number: str | int,
    ) -> AccountProof: ...

    def normalize_address(self, address: str) -> str: ...

    async def close(self) -> None: ...


class RequestRateLimiter:
    def __init__(self, minimum_interval: float):
        self.minimum_interval = minimum_interval
        self._lock = asyncio.Lock()
        self._last_request_at = 0.0

    async def wait(self) -> None:
        async with self._lock:
            remaining = self.minimum_interval - (monotonic() - self._last_request_at)
            if remaining > 0:
                await asyncio.sleep(remaining)
            self._last_request_at = monotonic()


class Web3EthereumRPC:
    """Async, rate-limited Ethereum JSON-RPC client."""

    def __init__(self, settings: Settings):
        if not settings.ethereum_rpc_url:
            raise ValueError("STATELESS_ETHEREUM_RPC_URL is not configured")
        self.settings = settings
        self.proof_rpc_url = (
            settings.ethereum_proof_rpc_url or settings.ethereum_rpc_url
        )
        self.provider = AsyncHTTPProvider(
            settings.ethereum_rpc_url,
            request_kwargs={
                "timeout": settings.ethereum_request_timeout_seconds,
            },
        )
        self.web3 = AsyncWeb3(self.provider)
        self.proof_provider = AsyncHTTPProvider(
            self.proof_rpc_url,
            request_kwargs={
                "timeout": settings.ethereum_request_timeout_seconds,
            },
        )
        self.proof_web3 = AsyncWeb3(self.proof_provider)
        self.rate_limiter = RequestRateLimiter(
            settings.ethereum_min_request_interval_seconds
        )

    @staticmethod
    def _rpc_error_details(exc: Web3RPCError) -> tuple[int | None, str]:
        response = exc.rpc_response or {}
        error = response.get("error", {})
        code = error.get("code")
        message = str(error.get("message") or exc.message)
        return code if isinstance(code, int) else None, message

    @classmethod
    def _is_transient_rpc_error(cls, exc: Web3RPCError) -> bool:
        code, message = cls._rpc_error_details(exc)
        normalized = message.lower()
        return code in {-32603, -32005, 429} or any(
            marker in normalized
            for marker in (
                "internal error",
                "rate limit",
                "too many requests",
                "temporarily unavailable",
                "timeout",
                "timed out",
                "try again",
            )
        )

    async def _request(self, operation, *, operation_name: str):
        last_error: Exception | None = None
        for attempt in range(1, self.settings.ethereum_retry_attempts + 1):
            await self.rate_limiter.wait()
            try:
                return await operation()
            except Web3RPCError as exc:
                if not self._is_transient_rpc_error(exc):
                    raise
                last_error = exc
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                last_error = exc
            if attempt >= self.settings.ethereum_retry_attempts:
                break
            delay = self.settings.ethereum_retry_backoff_seconds * (2 ** (attempt - 1))
            if delay:
                await asyncio.sleep(delay)
        assert last_error is not None
        rpc_code: int | None = None
        provider_message: str | None = None
        if isinstance(last_error, Web3RPCError):
            rpc_code, provider_message = self._rpc_error_details(last_error)
            provider_error = (
                f"RPC {rpc_code}: {provider_message}"
                if rpc_code is not None
                else provider_message
            )
        else:
            provider_error = f"{type(last_error).__name__}: {last_error}"
        raise EthereumRPCRequestError(
            operation_name=operation_name,
            attempts=self.settings.ethereum_retry_attempts,
            provider_error=provider_error,
            rpc_code=rpc_code,
            provider_message=provider_message,
        ) from last_error

    async def chain_id(self) -> int:
        primary_chain_id = int(
            await self._request(
                lambda: self.web3.eth.chain_id,
                operation_name="eth_chainId on data RPC",
            )
        )
        if self.proof_rpc_url != self.settings.ethereum_rpc_url:
            proof_chain_id = int(
                await self._request(
                    lambda: self.proof_web3.eth.chain_id,
                    operation_name="eth_chainId on proof RPC",
                )
            )
            if proof_chain_id != primary_chain_id:
                raise ValueError(
                    "Ethereum data and proof RPC endpoints use different chains: "
                    f"{primary_chain_id} and {proof_chain_id}"
                )
        return primary_chain_id

    async def pin_block(self, identifier: str | int) -> PinnedBlock:
        block = await self._request(
            lambda: self.web3.eth.get_block(
                identifier,
                full_transactions=False,
            ),
            operation_name=f"eth_getBlockByNumber({identifier}, false)",
        )
        return PinnedBlock(
            number=int(block["number"]),
            hash=as_hex(block["hash"]),
            state_root=as_hex(block["stateRoot"]),
            timestamp=datetime.fromtimestamp(
                int(block["timestamp"]),
                tz=timezone.utc,
            ),
        )

    async def discover_recent_addresses(
        self,
        *,
        block_number: int,
        account_count: int,
        scan_depth: int,
    ) -> list[str]:
        addresses: list[str] = []
        seen: set[str] = set()

        for offset in range(scan_depth):
            current_number = block_number - offset
            if current_number < 0 or len(addresses) >= account_count:
                break
            try:
                block = await self._request(
                    lambda number=current_number: self.web3.eth.get_block(
                        number,
                        full_transactions=True,
                    ),
                    operation_name=(
                        f"eth_getBlockByNumber({current_number}, true) "
                        "during address discovery"
                    ),
                )
            except EthereumRPCRequestError:
                continue
            for transaction in block["transactions"]:
                for candidate in (transaction.get("from"), transaction.get("to")):
                    if not candidate:
                        continue
                    normalized = self.normalize_address(str(candidate))
                    identity = normalized.lower()
                    if identity in seen:
                        continue
                    seen.add(identity)
                    addresses.append(normalized)
                    if len(addresses) >= account_count:
                        break
                if len(addresses) >= account_count:
                    break

        return addresses

    async def get_account_proof(
        self,
        address: str,
        block_number: str | int,
    ) -> AccountProof:
        block_quantity = (
            hex(block_number) if isinstance(block_number, int) else block_number
        )
        result = await self._request(
            lambda: self.proof_web3.manager.coro_request(
                RPCEndpoint("eth_getProof"),
                [address, [], block_quantity],
            ),
            operation_name=f"eth_getProof({address}, block {block_number})",
        )
        account_proof = [as_hex(node) for node in result["accountProof"]]
        return AccountProof(
            address=self.normalize_address(result.get("address", address)),
            nonce=int(result["nonce"], 16),
            balance=int(result["balance"], 16),
            storage_root=as_hex(result["storageHash"]),
            code_hash=as_hex(result["codeHash"]),
            account_proof=account_proof,
            proof_state_root=account_proof_state_root(account_proof),
        )

    def normalize_address(self, address: str) -> str:
        return Web3.to_checksum_address(address)

    async def close(self) -> None:
        await self.provider.disconnect()
        await self.proof_provider.disconnect()


def default_rpc_factory(settings: Settings) -> EthereumRPC:
    return Web3EthereumRPC(settings)
