"""Add webauthn_credentials table for site passkey (Face ID) login

Registered once per device the visitor opts into, right after a normal
OTP-verified login on the recovery-portal site (yaw.hsfmvps.shop) -- see
app/cabinet/routes/site_trial.py's /webauthn/register-* and /login-*
endpoints. Fixes the specific case a plain localStorage session can't:
adding the site to the iOS home screen puts it in a *different* storage
partition than Safari, so the visitor is asked for email/OTP again even
though nothing about their account changed -- a passkey survives that
because it lives in the device's Keychain, not site storage.

Revision ID: 0097
Revises: 0096
Create Date: 2026-07-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = '0097'
down_revision: Union[str, None] = '0096'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = 'webauthn_credentials'


def upgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table(_TABLE):
        return

    op.create_table(
        _TABLE,
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('credential_id', sa.String(length=255), nullable=False, unique=True),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('sign_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('device_label', sa.String(length=120), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_webauthn_credentials_user', _TABLE, ['user_id'], unique=False)
    op.create_index('ix_webauthn_credentials_credential_id', _TABLE, ['credential_id'], unique=True)


def downgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table(_TABLE):
        op.drop_index('ix_webauthn_credentials_credential_id', table_name=_TABLE)
        op.drop_index('ix_webauthn_credentials_user', table_name=_TABLE)
        op.drop_table(_TABLE)
