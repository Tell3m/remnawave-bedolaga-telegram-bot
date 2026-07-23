"""users: add site_trial_fingerprint for stronger site-trial abuse detection

site_trial_device_id (0095) is generated client-side and persisted in
localStorage -- trivially reset by clearing browser data, which is exactly
how a repeat trial claim slipped through despite that check. This column
stores an open-source FingerprintJS hash instead (canvas/WebGL/font/etc
derived), which survives a storage clear since nothing about it is stored
on the client at all -- it's recomputed fresh from device/browser
characteristics every time.

Neither signal alone is treated as authoritative (see
app/cabinet/routes/site_trial.py's _compute_abuse_signal_count): a claim is
only blocked when at least 2 of {device_id match, fingerprint match,
IP-subnet already used} agree, so a single false positive (e.g. two
different phones of the same model producing a similar fingerprint) can't
lock out a legitimate visitor on its own.

Revision ID: 0096
Revises: 0095
Create Date: 2026-07-23
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = '0096'
down_revision: Union[str, None] = '0095'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = 'users'
_COLUMN = 'site_trial_fingerprint'


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
            'ix_users_site_trial_fingerprint',
            _TABLE,
            [_COLUMN],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _column_exists(bind):
        op.drop_index('ix_users_site_trial_fingerprint', table_name=_TABLE)
        op.drop_column(_TABLE, _COLUMN)
