from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import Enum as SqlEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobKind(str, Enum):
    SYSTEM = "system"
    ETHEREUM_IMPORT = "ethereum_import"
    TREE_GENERATION = "tree_generation"
    PROOF_EXPERIMENT = "proof_experiment"


class DatasetStatus(str, Enum):
    QUEUED = "queued"
    IMPORTING = "importing"
    READY = "ready"
    FAILED = "failed"


class AddressSource(str, Enum):
    EXPLICIT = "explicit"
    RECENT_TRANSACTIONS = "recent_transactions"
    LOCAL_JSON = "local_json"


class StateMode(str, Enum):
    PINNED = "pinned"
    ROLLING_LATEST = "rolling_latest"
    LOCAL_IMPORT = "local_import"


class TreeStatus(str, Enum):
    QUEUED = "queued"
    BUILDING = "building"
    READY = "ready"
    FAILED = "failed"


class TreeType(str, Enum):
    MERKLE_PATRICIA = "merkle_patricia"
    POSEIDON_MERKLE = "poseidon_merkle"
    VERKLE = "verkle"


class TreeHashFunction(str, Enum):
    KECCAK = "keccak"
    POSEIDON = "poseidon"
    KZG = "kzg"


class ProofStatus(str, Enum):
    QUEUED = "queued"
    PROVING = "proving"
    READY = "ready"
    FAILED = "failed"


def enum_values(enum_class: type[Enum]) -> list[str]:
    return [member.value for member in enum_class]


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint("progress >= 0 AND progress <= 100", name="ck_jobs_progress"),
        Index("ix_jobs_status_created_at", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    kind: Mapped[JobKind] = mapped_column(
        SqlEnum(
            JobKind,
            values_callable=enum_values,
            native_enum=False,
            length=32,
        ),
        nullable=False,
    )
    status: Mapped[JobStatus] = mapped_column(
        SqlEnum(
            JobStatus,
            values_callable=enum_values,
            native_enum=False,
            length=16,
        ),
        default=JobStatus.QUEUED,
        nullable=False,
    )
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    parameters: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class EthereumDataset(Base):
    __tablename__ = "ethereum_datasets"
    __table_args__ = (
        Index(
            "ix_ethereum_datasets_status_created_at",
            "status",
            "created_at",
        ),
        Index(
            "ix_ethereum_datasets_chain_block",
            "chain_id",
            "block_number",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    network: Mapped[str] = mapped_column(String(40), nullable=False)
    chain_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rpc_provider: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_block: Mapped[str] = mapped_column(String(32), nullable=False)
    block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    block_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    state_root: Mapped[str | None] = mapped_column(String(66), nullable=True)
    block_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    address_source: Mapped[AddressSource] = mapped_column(
        SqlEnum(
            AddressSource,
            values_callable=enum_values,
            native_enum=False,
            length=32,
        ),
        nullable=False,
    )
    state_mode: Mapped[StateMode] = mapped_column(
        SqlEnum(
            StateMode,
            values_callable=enum_values,
            native_enum=False,
            length=24,
        ),
        default=StateMode.PINNED,
        nullable=False,
    )
    requested_account_count: Mapped[int] = mapped_column(Integer, nullable=False)
    imported_account_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    scan_depth: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_state_root_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    status: Mapped[DatasetStatus] = mapped_column(
        SqlEnum(
            DatasetStatus,
            values_callable=enum_values,
            native_enum=False,
            length=16,
        ),
        default=DatasetStatus.QUEUED,
        nullable=False,
    )
    artifact_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    job_id: Mapped[str] = mapped_column(
        ForeignKey("jobs.id", ondelete="RESTRICT"),
        unique=True,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    fetched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    accounts: Mapped[list["EthereumAccount"]] = relationship(
        back_populates="dataset",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    trees: Mapped[list["GeneratedTree"]] = relationship(
        back_populates="dataset",
    )


class EthereumAccount(Base):
    __tablename__ = "ethereum_accounts"
    __table_args__ = (
        UniqueConstraint(
            "dataset_id",
            "address",
            name="uq_ethereum_accounts_dataset_address",
        ),
        Index("ix_ethereum_accounts_dataset_id", "dataset_id"),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    dataset_id: Mapped[str] = mapped_column(
        ForeignKey("ethereum_datasets.id", ondelete="CASCADE"),
        nullable=False,
    )
    address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    secure_trie_key: Mapped[str] = mapped_column(String(66), nullable=False)
    account_rlp: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(78), nullable=False)
    balance: Mapped[str] = mapped_column(String(78), nullable=False)
    storage_root: Mapped[str] = mapped_column(String(66), nullable=False)
    code_hash: Mapped[str] = mapped_column(String(66), nullable=False)
    account_proof: Mapped[list] = mapped_column(JSON, nullable=False)
    proof_node_count: Mapped[int] = mapped_column(Integer, nullable=False)
    proof_state_root: Mapped[str | None] = mapped_column(
        String(66),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    dataset: Mapped[EthereumDataset] = relationship(back_populates="accounts")


class GeneratedTree(Base):
    __tablename__ = "generated_trees"
    __table_args__ = (
        Index("ix_generated_trees_status_created_at", "status", "created_at"),
        Index("ix_generated_trees_dataset_id", "dataset_id"),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    dataset_id: Mapped[str] = mapped_column(
        ForeignKey("ethereum_datasets.id", ondelete="RESTRICT"),
        nullable=False,
    )
    job_id: Mapped[str] = mapped_column(
        ForeignKey("jobs.id", ondelete="RESTRICT"),
        unique=True,
        nullable=False,
    )
    tree_type: Mapped[TreeType] = mapped_column(
        SqlEnum(
            TreeType,
            values_callable=enum_values,
            native_enum=False,
            length=32,
        ),
        nullable=False,
    )
    hash_function: Mapped[TreeHashFunction] = mapped_column(
        SqlEnum(
            TreeHashFunction,
            values_callable=enum_values,
            native_enum=False,
            length=16,
        ),
        nullable=False,
    )
    width: Mapped[int] = mapped_column(Integer, default=16, nullable=False)
    requested_key_count: Mapped[int] = mapped_column(Integer, nullable=False)
    key_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    node_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    leaf_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    extension_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    branch_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_depth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    root_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    build_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[TreeStatus] = mapped_column(
        SqlEnum(
            TreeStatus,
            values_callable=enum_values,
            native_enum=False,
            length=16,
        ),
        default=TreeStatus.QUEUED,
        nullable=False,
    )
    configuration: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    artifact_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    storage_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    dataset: Mapped[EthereumDataset] = relationship(back_populates="trees")
    proof_experiments: Mapped[list["ProofExperiment"]] = relationship(
        back_populates="tree",
    )


class ProofExperiment(Base):
    __tablename__ = "proof_experiments"
    __table_args__ = (
        Index(
            "ix_proof_experiments_status_created_at",
            "status",
            "created_at",
        ),
        Index("ix_proof_experiments_tree_id", "tree_id"),
        CheckConstraint(
            "requested_key_count > 0",
            name="ck_proof_experiments_requested_key_count",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    tree_id: Mapped[str] = mapped_column(
        ForeignKey("generated_trees.id", ondelete="RESTRICT"),
        nullable=False,
    )
    job_id: Mapped[str] = mapped_column(
        ForeignKey("jobs.id", ondelete="RESTRICT"),
        unique=True,
        nullable=False,
    )
    prover_type: Mapped[str] = mapped_column(String(64), nullable=False)
    verifier_type: Mapped[str] = mapped_column(String(64), nullable=False)
    setup_type: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    width: Mapped[int] = mapped_column(Integer, nullable=False)
    tree_type: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_key_count: Mapped[int] = mapped_column(Integer, nullable=False)
    num_keys_tree: Mapped[int] = mapped_column(Integer, nullable=False)
    selection_seed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sampled_keys: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    proof_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    proving_time: Mapped[float | None] = mapped_column(Float, nullable=True)
    verification_time: Mapped[float | None] = mapped_column(Float, nullable=True)
    verified: Mapped[bool | None] = mapped_column(nullable=True)
    root_hash: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status: Mapped[ProofStatus] = mapped_column(
        SqlEnum(
            ProofStatus,
            values_callable=enum_values,
            native_enum=False,
            length=16,
        ),
        default=ProofStatus.QUEUED,
        nullable=False,
    )
    artifact_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    tree: Mapped[GeneratedTree] = relationship(back_populates="proof_experiments")
