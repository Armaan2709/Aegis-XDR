"""initial_schema_sprint21

Revision ID: 5d18d07315a7
Revises: None
Create Date: 2026-08-11 19:01:21.061907

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5d18d07315a7'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from app.models.base import Base
    import app.models  # noqa: F401

    bind = op.get_bind()
    Base.metadata.create_all(bind)


def downgrade() -> None:
    from app.models.base import Base
    import app.models  # noqa: F401

    bind = op.get_bind()
    Base.metadata.drop_all(bind)
