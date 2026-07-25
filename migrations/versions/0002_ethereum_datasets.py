"""Add reproducible Ethereum datasets and account proofs.

Revision ID: 0002_ethereum_data
Revises: 0001_phase_1
Create Date: 2026-07-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_ethereum_data"
down_revision: str | None = "0001_phase_1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ethereum_datasets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("network", sa.String(length=40), nullable=False),
        sa.Column("chain_id", sa.Integer(), nullable=True),
        sa.Column("rpc_provider", sa.String(length=255), nullable=False),
        sa.Column("requested_block", sa.String(length=32), nullable=False),
        sa.Column("block_number", sa.Integer(), nullable=True),
        sa.Column("block_hash", sa.String(length=66), nullable=True),
        sa.Column("state_root", sa.String(length=66), nullable=True),
        sa.Column("block_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "address_source",
            sa.Enum(
                "explicit",
                "recent_transactions",
                name="addresssource",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("requested_account_count", sa.Integer(), nullable=False),
        sa.Column("imported_account_count", sa.Integer(), nullable=False),
        sa.Column("scan_depth", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "queued",
                "importing",
                "ready",
                "failed",
                name="datasetstatus",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("artifact_path", sa.String(length=500), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id"),
    )
    op.create_index(
        "ix_ethereum_datasets_chain_block",
        "ethereum_datasets",
        ["chain_id", "block_number"],
        unique=False,
    )
    op.create_index(
        "ix_ethereum_datasets_status_created_at",
        "ethereum_datasets",
        ["status", "created_at"],
        unique=False,
    )

    op.create_table(
        "ethereum_accounts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("dataset_id", sa.String(length=36), nullable=False),
        sa.Column("address", sa.String(length=42), nullable=False),
        sa.Column("secure_trie_key", sa.String(length=66), nullable=False),
        sa.Column("account_rlp", sa.Text(), nullable=False),
        sa.Column("nonce", sa.String(length=78), nullable=False),
        sa.Column("balance", sa.String(length=78), nullable=False),
        sa.Column("storage_root", sa.String(length=66), nullable=False),
        sa.Column("code_hash", sa.String(length=66), nullable=False),
        sa.Column("account_proof", sa.JSON(), nullable=False),
        sa.Column("proof_node_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["dataset_id"],
            ["ethereum_datasets.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "dataset_id",
            "address",
            name="uq_ethereum_accounts_dataset_address",
        ),
    )
    op.create_index(
        "ix_ethereum_accounts_dataset_id",
        "ethereum_accounts",
        ["dataset_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_ethereum_accounts_dataset_id",
        table_name="ethereum_accounts",
    )
    op.drop_table("ethereum_accounts")
    op.drop_index(
        "ix_ethereum_datasets_status_created_at",
        table_name="ethereum_datasets",
    )
    op.drop_index(
        "ix_ethereum_datasets_chain_block",
        table_name="ethereum_datasets",
    )
    op.drop_table("ethereum_datasets")
