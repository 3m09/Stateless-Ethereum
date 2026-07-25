"""Add persisted generated trees and build metadata.

Revision ID: 0003_generated_trees
Revises: 0002_ethereum_data
Create Date: 2026-07-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_generated_trees"
down_revision: str | None = "0002_ethereum_data"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "generated_trees",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("dataset_id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column(
            "tree_type",
            sa.Enum(
                "merkle_patricia",
                name="treetype",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "hash_function",
            sa.Enum(
                "keccak",
                name="treehashfunction",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("width", sa.Integer(), nullable=False),
        sa.Column("requested_key_count", sa.Integer(), nullable=False),
        sa.Column("key_count", sa.Integer(), nullable=False),
        sa.Column("node_count", sa.Integer(), nullable=False),
        sa.Column("leaf_count", sa.Integer(), nullable=False),
        sa.Column("extension_count", sa.Integer(), nullable=False),
        sa.Column("branch_count", sa.Integer(), nullable=False),
        sa.Column("max_depth", sa.Integer(), nullable=False),
        sa.Column("root_hash", sa.String(length=66), nullable=True),
        sa.Column("build_duration_ms", sa.Integer(), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "queued",
                "building",
                "ready",
                "failed",
                name="treestatus",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("artifact_path", sa.String(length=500), nullable=True),
        sa.Column("storage_path", sa.String(length=500), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["dataset_id"],
            ["ethereum_datasets.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id"),
    )
    op.create_index(
        "ix_generated_trees_dataset_id",
        "generated_trees",
        ["dataset_id"],
        unique=False,
    )
    op.create_index(
        "ix_generated_trees_status_created_at",
        "generated_trees",
        ["status", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_generated_trees_status_created_at",
        table_name="generated_trees",
    )
    op.drop_index(
        "ix_generated_trees_dataset_id",
        table_name="generated_trees",
    )
    op.drop_table("generated_trees")
