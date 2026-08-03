"""users: add site_trial_device_id for site-trial abuse prevention

The public site-trial-claim endpoint (app/cabinet/routes/site_trial.py) used
to key eligibility purely by email via User.is_trial_already_used() -- since
a fresh email always creates a fresh User row with no subscription history,
nothing stopped the same physical device from claiming the trial repeatedly
under different emails. This column stores a client-generated, localStorage-
persisted device id at first-claim time so a later claim attempt from a
DIFFERENT email but the SAME device can be recognized and blocked.

Revision ID: hs0001
Revises: 0103
Create Date: 2026-07-22
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = 'hs0001'
down_revision: Union[str, None] = '0103'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = 'users'
_COLUMN = 'site_trial_device_id'


def _column_exists(bind: sa.engine.Connection) -> bool:
    inspector = sa.inspect(bind)
    if not inspector.has_table(_TABLE):
        return False
    return any(col['name'] == _COLUMN for col in inspector.get_columns(_TABLE))


def upgrade() -> None:
    bind = op.get_bind()
    if not sa.inspect(bind).has_table(_TABLE):
        return
    if not _column_exists(bind):
        op.add_column(
            _TABLE,
            sa.Column(_COLUMN, sa.String(length=64), nullable=True),
        )
        op.create_index(
            'ix_users_site_trial_device_id',
            _TABLE,
            [_COLUMN],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _column_exists(bind):
        op.drop_index('ix_users_site_trial_device_id', table_name=_TABLE)
        op.drop_column(_TABLE, _COLUMN)
