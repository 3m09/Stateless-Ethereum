"""Allow local trie JSON datasets without original addresses.

Revision ID: 0006_local_json_imports
Revises: 0005_large_state_imports
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_local_json_imports"
down_revision: str | None = "0005_large_state_imports"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("ethereum_accounts") as batch_op:
        batch_op.alter_column(
            "address",
            existing_type=sa.String(length=42),
            nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("ethereum_accounts") as batch_op:
        batch_op.alter_column(
            "address",
            existing_type=sa.String(length=42),
            nullable=False,
        )
