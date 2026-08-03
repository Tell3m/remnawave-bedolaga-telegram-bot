"""users: add account_link_hint_sent_at for the account-merge awareness nudge

Tracks whether a user has already been sent the one-time "link your other
account" hint (site/email users missing telegram_id get told to link
Telegram; Telegram-only users missing email get the reciprocal hint). A
persistent per-user timestamp is required rather than the in-memory
_notified_users cache monitoring_service.py already uses for transient
conditions (expiring subscription etc.) -- unlike those, "no telegram_id"/
"no email" doesn't resolve itself over time, so without persistence the
periodic monitoring cycle would re-send this hint to the same users on
every restart of the bot process forever.

Revision ID: hs0005
Revises: hs0004
Create Date: 2026-08-02
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = 'hs0005'
down_revision: Union[str, None] = 'hs0004'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = 'users'
_COLUMN = 'account_link_hint_sent_at'


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
            sa.Column(_COLUMN, sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _column_exists(bind):
        op.drop_column(_TABLE, _COLUMN)
