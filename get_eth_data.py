"""Collect real Ethereum account trie key/value pairs."""

import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar
from urllib.parse import urlsplit

import rlp
from dotenv import load_dotenv
from eth_utils import decode_hex, encode_hex, keccak
from web3 import Web3

MAX_ACCOUNTS = 2048
T = TypeVar("T")

# Load the repository environment even when this script is launched elsewhere.
ENV_PATH = Path(__file__).resolve().with_name(".env")
load_dotenv(dotenv_path=ENV_PATH, override=True)

INFURA_API_KEY = os.getenv("INFURA_API_KEY")
RPC_URL = (
    os.getenv("GET_ETH_DATA_RPC_URL")
    or os.getenv("STATELESS_ETHEREUM_RPC_URL")
    or (
        f"https://mainnet.infura.io/v3/{INFURA_API_KEY}"
        if INFURA_API_KEY
        else None
    )
)
RETRY_ATTEMPTS = int(os.getenv("GET_ETH_DATA_RETRY_ATTEMPTS", "3"))
RETRY_BACKOFF_SECONDS = float(
    os.getenv("GET_ETH_DATA_RETRY_BACKOFF_SECONDS", "0.5")
)
MIN_REQUEST_INTERVAL_SECONDS = float(
    os.getenv("GET_ETH_DATA_MIN_REQUEST_INTERVAL_SECONDS", "0.05")
)

w3 = (
    Web3(
        Web3.HTTPProvider(
            RPC_URL,
            request_kwargs={"timeout": 30},
        )
    )
    if RPC_URL
    else None
)
last_request_at = 0.0


def rpc_call(operation: Callable[[], T], label: str) -> T:
    """Execute a paced RPC call with bounded exponential retries."""

    global last_request_at
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        remaining = MIN_REQUEST_INTERVAL_SECONDS - (
            time.monotonic() - last_request_at
        )
        if remaining > 0:
            time.sleep(remaining)
        last_request_at = time.monotonic()
        try:
            return operation()
        except Exception:
            if attempt >= RETRY_ATTEMPTS:
                raise
            delay = RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1))
            print(
                f"  {label} failed (attempt {attempt}/{RETRY_ATTEMPTS}); "
                f"retrying in {delay:.1f}s"
            )
            if delay > 0:
                time.sleep(delay)
    raise RuntimeError(f"{label} did not run")


def fetch_trie_kv_pairs(
    num_accounts: int = 50,
    output_file: str | None = None,
    block_number: str | int = "latest",
    *,
    scan_depth: int = 100,
) -> dict[str, str] | None:
    """Fetch authentic Ethereum account values for trie experiments."""

    if not 1 <= num_accounts <= MAX_ACCOUNTS:
        raise ValueError(f"num_accounts must be between 1 and {MAX_ACCOUNTS}")
    if w3 is None or RPC_URL is None:
        print(f"Ethereum RPC credentials are missing in {ENV_PATH}")
        return None

    try:
        chain_id = rpc_call(lambda: w3.eth.chain_id, "eth_chainId")
    except Exception as exc:  # noqa: BLE001 - report RPC startup failures
        print(f"Failed to connect to Ethereum RPC: {type(exc).__name__}")
        return None
    if chain_id != 1:
        print(f"Expected Ethereum mainnet (chain ID 1), received {chain_id}")
        return None

    block = rpc_call(
        lambda: w3.eth.get_block(block_number),
        f"fetching block {block_number}",
    )
    provider = urlsplit(RPC_URL).hostname or "configured provider"

    print(f"Connected to Ethereum mainnet through {provider}")
    print(f"Discovery anchor block: {block['number']}")
    print("=" * 60)

    # Over-collect candidates because individual proof requests can fail.
    candidate_target = num_accounts + max(256, num_accounts // 2)
    addresses: list[str] = []
    seen: set[str] = set()
    for offset in range(scan_depth):
        if len(addresses) >= candidate_target:
            break
        current_block = int(block["number"]) - offset
        try:
            recent_block = rpc_call(
                lambda number=current_block: w3.eth.get_block(
                    number,
                    full_transactions=True,
                ),
                f"fetching block {current_block}",
            )
        except Exception as exc:  # noqa: BLE001 - skip an unavailable block
            print(f"Skipping block {current_block}: {type(exc).__name__}")
            continue

        for transaction in recent_block.transactions:
            for candidate in (transaction.get("from"), transaction.get("to")):
                if not candidate:
                    continue
                address = Web3.to_checksum_address(candidate)
                identity = address.lower()
                if identity in seen:
                    continue
                seen.add(identity)
                addresses.append(address)
                if len(addresses) >= candidate_target:
                    break
            if len(addresses) >= candidate_target:
                break

    print(f"\nCollected {len(addresses)} candidate addresses")
    print("Fetching account states and calculating KV pairs...\n")

    trie_kv_data: dict[str, str] = {}
    failures = 0
    for address in addresses:
        if len(trie_kv_data) >= num_accounts:
            break
        try:
            proof = rpc_call(
                lambda current_address=address: w3.eth.get_proof(
                    current_address,
                    [],
                    block_number,
                ),
                f"proof for {address}",
            )

            trie_key = keccak(decode_hex(address))
            trie_value = rlp.encode(
                [
                    proof.nonce,
                    proof.balance,
                    bytes(proof.storageHash),
                    bytes(proof.codeHash),
                ]
            )
            hex_key = encode_hex(trie_key)
            hex_value = encode_hex(trie_value)
            trie_kv_data[hex_key] = hex_value

            completed = len(trie_kv_data)
            print(f"[{completed}/{num_accounts}] Processed Address: {address}")
            print(f"  Key:   {hex_key}")
            print(f"  Value: {hex_value[:20]}...{hex_value[-10:]}\n")
        except Exception as exc:  # noqa: BLE001 - continue with next candidate
            failures += 1
            print(
                f"  Skipping {address} after {RETRY_ATTEMPTS} attempts: "
                f"{type(exc).__name__}\n"
            )

    if output_file is not None:
        with open(output_file, "w", encoding="utf-8") as handle:
            json.dump(trie_kv_data, handle, indent=4)

    print("=" * 60)
    print(
        f"Complete: {len(trie_kv_data)}/{num_accounts} accounts, "
        f"{failures} failed candidates"
    )
    if len(trie_kv_data) < num_accounts:
        print(
            "The requested total was not reached. Increase scan_depth or use "
            "another proof-capable RPC endpoint."
        )
    return trie_kv_data


if __name__ == "__main__":
    fetch_trie_kv_pairs(
    num_accounts=128,
    output_file="ethereum_trie_data.json",
)
