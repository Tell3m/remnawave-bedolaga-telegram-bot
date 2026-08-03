"""Add site_notifications and push_subscriptions tables

Backend for the recovery-portal site's notification bell + Web Push:
site_notifications is the per-user history shown in the bell (title/body/
deep_link, read/unread), push_subscriptions holds the browser Push API
endpoint + encryption keys registered after the visitor grants
notification permission. Both are written by NotificationDeliveryService
and the traffic-warning check in monitoring_service.py.

Revision ID: hs0004
Revises: hs0003
Create Date: 2026-07-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = 'hs0004'
down_revision: Union[str, None] = 'hs0003'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_NOTIFICATIONS_TABLE = 'site_notifications'
_PUSH_TABLE = 'push_subscriptions'


def upgrade() -> None:
    bind = op.get_bind()

    if not sa.inspect(bind).has_table(_NOTIFICATIONS_TABLE):
        op.create_table(
            _NOTIFICATIONS_TABLE,
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
            sa.Column('type', sa.String(length=64), nullable=False),
            sa.Column('title', sa.String(length=200), nullable=False),
            sa.Column('body', sa.Text(), nullable=False),
            sa.Column('deep_link', sa.String(length=500), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column('read_at', sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index(
            'ix_site_notifications_user_created', _NOTIFICATIONS_TABLE, ['user_id', 'created_at'], unique=False
        )

    if not sa.inspect(bind).has_table(_PUSH_TABLE):
        op.create_table(
            _PUSH_TABLE,
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
            sa.Column('endpoint', sa.String(length=500), nullable=False, unique=True),
            sa.Column('p256dh_key', sa.String(length=255), nullable=False),
            sa.Column('auth_key', sa.String(length=255), nullable=False),
            sa.Column('user_agent', sa.String(length=300), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index('ix_push_subscriptions_user', _PUSH_TABLE, ['user_id'], unique=False)
        op.create_index('ix_push_subscriptions_endpoint', _PUSH_TABLE, ['endpoint'], unique=True)


def downgrade() -> None:
    bind = op.get_bind()

    if sa.inspect(bind).has_table(_PUSH_TABLE):
        op.drop_index('ix_push_subscriptions_endpoint', table_name=_PUSH_TABLE)
        op.drop_index('ix_push_subscriptions_user', table_name=_PUSH_TABLE)
        op.drop_table(_PUSH_TABLE)

    if sa.inspect(bind).has_table(_NOTIFICATIONS_TABLE):
        op.drop_index('ix_site_notifications_user_created', table_name=_NOTIFICATIONS_TABLE)
        op.drop_table(_NOTIFICATIONS_TABLE)
