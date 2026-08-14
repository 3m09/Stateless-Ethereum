import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.limits import MAX_EXPERIMENT_KEYS, is_power_of_two_account_count
from app.models import AddressSource, DatasetStatus, StateMode
from app.schemas import JobRead

ETHEREUM_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
BLOCK_TAGS = {"latest", "safe", "finalized"}


class EthereumImportCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    block: str | int = "latest"
    address_source: AddressSource = AddressSource.RECENT_TRANSACTIONS
    state_mode: StateMode = StateMode.ROLLING_LATEST
    addresses: list[str] = Field(
        default_factory=list,
        max_length=MAX_EXPERIMENT_KEYS,
    )
    account_count: int = Field(default=32, ge=1, le=MAX_EXPERIMENT_KEYS)
    scan_depth: int = Field(default=100, ge=1, le=512)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not cleaned:
            raise ValueError("Dataset name cannot be blank")
        return cleaned

    @field_validator("block")
    @classmethod
    def validate_block(cls, value: str | int) -> str | int:
        if isinstance(value, int):
            if value < 0:
                raise ValueError("Block number cannot be negative")
            return value
        cleaned = value.strip().lower()
        if cleaned in BLOCK_TAGS:
            return cleaned
        if cleaned.isdigit():
            return int(cleaned)
        raise ValueError("Block must be a number, latest, safe, or finalized")

    @field_validator("addresses")
    @classmethod
    def validate_addresses(cls, values: list[str]) -> list[str]:
        unique: list[str] = []
        seen: set[str] = set()
        for value in values:
            cleaned = value.strip()
            if not ETHEREUM_ADDRESS.fullmatch(cleaned):
                raise ValueError(f"Invalid Ethereum address: {cleaned}")
            identity = cleaned.lower()
            if identity not in seen:
                seen.add(identity)
                unique.append(cleaned)
        return unique

    @model_validator(mode="after")
    def validate_source(self) -> "EthereumImportCreate":
        if self.state_mode == StateMode.ROLLING_LATEST and self.block != "latest":
            raise ValueError("Rolling latest mode requires BLOCK=latest")
        if self.address_source == AddressSource.EXPLICIT:
            if not self.addresses:
                raise ValueError("At least one explicit address is required")
            self.account_count = len(self.addresses)
        if not is_power_of_two_account_count(self.account_count):
            raise ValueError(
                "Account count must be a power of two from 1 through 2048"
            )
        return self


class LocalEthereumImportCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not cleaned:
            raise ValueError("Dataset name cannot be blank")
        return cleaned


class EthereumDatasetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    network: str
    chain_id: int | None
    rpc_provider: str
    requested_block: str
    block_number: int | None
    block_hash: str | None
    state_root: str | None
    block_timestamp: datetime | None
    address_source: AddressSource
    state_mode: StateMode
    requested_account_count: int
    imported_account_count: int
    scan_depth: int
    observed_state_root_count: int
    status: DatasetStatus
    artifact_path: str | None
    error: str | None
    job_id: str
    created_at: datetime
    fetched_at: datetime | None


class EthereumAccountRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    dataset_id: str
    address: str | None
    secure_trie_key: str
    account_rlp: str
    nonce: str
    balance: str
    storage_root: str
    code_hash: str
    account_proof: list[Any]
    proof_node_count: int
    proof_state_root: str | None
    created_at: datetime


class EthereumImportAccepted(BaseModel):
    dataset: EthereumDatasetRead
    job: JobRead
