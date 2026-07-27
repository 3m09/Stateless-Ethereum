"""Add state-mode metadata for large Ethereum imports.

Revision ID: 0005_large_state_imports
Revises: 0004_proof_experiments
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_large_state_imports"
down_revision: str | None = "0004_proof_experiments"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "ethereum_datasets",
        sa.Column(
            "state_mode",
            sa.String(length=24),
            nullable=False,
            server_default="pinned",
        ),
    )
    op.add_column(
        "ethereum_datasets",
        sa.Column(
            "observed_state_root_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "ethereum_accounts",
        sa.Column("proof_state_root", sa.String(length=66), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("ethereum_accounts", "proof_state_root")
    op.drop_column("ethereum_datasets", "observed_state_root_count")
    op.drop_column("ethereum_datasets", "state_mode")
