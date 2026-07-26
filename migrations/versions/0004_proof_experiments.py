"""Add persisted proving and verification experiments.

Revision ID: 0004_proof_experiments
Revises: 0003_generated_trees
Create Date: 2026-07-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_proof_experiments"
down_revision: str | None = "0003_generated_trees"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "proof_experiments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("tree_id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("prover_type", sa.String(length=64), nullable=False),
        sa.Column("verifier_type", sa.String(length=64), nullable=False),
        sa.Column("setup_type", sa.String(length=64), nullable=False),
        sa.Column("width", sa.Integer(), nullable=False),
        sa.Column("tree_type", sa.String(length=32), nullable=False),
        sa.Column("requested_key_count", sa.Integer(), nullable=False),
        sa.Column("num_keys_tree", sa.Integer(), nullable=False),
        sa.Column("selection_seed", sa.Integer(), nullable=False),
        sa.Column("sampled_keys", sa.JSON(), nullable=False),
        sa.Column("proof_size", sa.Integer(), nullable=True),
        sa.Column("proving_time", sa.Float(), nullable=True),
        sa.Column("verification_time", sa.Float(), nullable=True),
        sa.Column("verified", sa.Boolean(), nullable=True),
        sa.Column("root_hash", sa.String(length=200), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "queued",
                "proving",
                "ready",
                "failed",
                name="proofstatus",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("artifact_path", sa.String(length=500), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "requested_key_count > 0",
            name="ck_proof_experiments_requested_key_count",
        ),
        sa.ForeignKeyConstraint(
            ["tree_id"],
            ["generated_trees.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id"),
    )
    op.create_index(
        "ix_proof_experiments_tree_id",
        "proof_experiments",
        ["tree_id"],
        unique=False,
    )
    op.create_index(
        "ix_proof_experiments_status_created_at",
        "proof_experiments",
        ["status", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_proof_experiments_status_created_at",
        table_name="proof_experiments",
    )
    op.drop_index(
        "ix_proof_experiments_tree_id",
        table_name="proof_experiments",
    )
    op.drop_table("proof_experiments")
