"""Notification bell + Web Push endpoints for the recovery-portal site.

Separate file from site_trial.py on purpose -- that file is already the
single largest, most actively-changing file in this whole feature area
(see the risk-of-conflict notes in the update playbook), so this stays
its own small, independently revertable unit. Reuses the exact same
site-session model everywhere else on the site: the browser holds a
cabinet refresh_token (from /request-code + /verify-code) and passes it
in the body of every call here, same as /cabinet-handoff and
/telegram-link-token in site_trial.py.

Two concerns live here:
1. The bell itself -- list/read the SiteNotification rows written by
   NotificationDeliveryService and the traffic-warning check.
2. Web Push subscription management -- register/remove the browser
   endpoint + keys that site_push_service.py sends to.
"""

from __future__ import annotations

import hashlib

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database.crud.user import get_user_by_id
from app.database.models import CabinetRefreshToken, PushSubscription, SiteNotification, UserStatus
from app.utils.cache import RateLimitCache

from ..auth import get_token_payload
from ..dependencies import get_cabinet_db
from ..ip_utils import get_client_ip


logger = structlog.get_logger(__name__)

router = APIRouter(prefix='/public/site-trial', tags=['Cabinet:Public'])


async def _resolve_site_session_user_id(db: AsyncSession, refresh_token: str) -> int:
    """Same validation as site_trial.py's /cabinet-handoff -- see that
    endpoint's docstring for why (must be a live, non-revoked cabinet
    refresh token, not just a well-formed JWT).
    """
    payload = get_token_payload(refresh_token, expected_type='refresh')
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid or expired session')

    try:
        user_id = int(payload.get('sub'))
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token payload') from error

    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    result = await db.execute(
        select(CabinetRefreshToken).where(
            CabinetRefreshToken.token_hash == token_hash,
            CabinetRefreshToken.revoked_at.is_(None),
        )
    )
    token_record = result.scalar_one_or_none()
    if not token_record or not token_record.is_valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Session no longer valid')

    user = await get_user_by_id(db, user_id)
    if not user or user.status != UserStatus.ACTIVE.value:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Account not active')

    return user_id


class SiteNotificationItem(BaseModel):
    id: int
    type: str
    title: str
    body: str
    deep_link: str | None = None
    created_at: str
    read: bool


class SiteNotificationListRequest(BaseModel):
    refresh_token: str = Field(..., description="The site session's refresh token")


class SiteNotificationListResponse(BaseModel):
    items: list[SiteNotificationItem]
    unread_count: int


@router.post('/notifications/list', response_model=SiteNotificationListResponse)
async def list_site_notifications(
    request: SiteNotificationListRequest,
    db: AsyncSession = Depends(get_cabinet_db),
):
    user_id = await _resolve_site_session_user_id(db, request.refresh_token)

    result = await db.execute(
        select(SiteNotification)
        .where(SiteNotification.user_id == user_id)
        .order_by(SiteNotification.created_at.desc())
        .limit(50)
    )
    rows = result.scalars().all()

    return SiteNotificationListResponse(
        items=[
            SiteNotificationItem(
                id=row.id,
                type=row.type,
                title=row.title,
                body=row.body,
                deep_link=row.deep_link,
                created_at=row.created_at.isoformat() if row.created_at else '',
                read=row.read_at is not None,
            )
            for row in rows
        ],
        unread_count=sum(1 for row in rows if row.read_at is None),
    )


class SiteNotificationReadRequest(BaseModel):
    refresh_token: str = Field(..., description="The site session's refresh token")
    notification_id: int | None = Field(None, description="Mark just this one read; omit to mark all read")


@router.post('/notifications/read')
async def mark_site_notifications_read(
    request: SiteNotificationReadRequest,
    db: AsyncSession = Depends(get_cabinet_db),
):
    user_id = await _resolve_site_session_user_id(db, request.refresh_token)

    stmt = (
        update(SiteNotification)
        .where(SiteNotification.user_id == user_id, SiteNotification.read_at.is_(None))
        .values(read_at=func.now())
    )
    if request.notification_id is not None:
        stmt = stmt.where(SiteNotification.id == request.notification_id)

    await db.execute(stmt)
    await db.commit()
    return {'status': 'ok'}


class SiteNotificationDismissRequest(BaseModel):
    refresh_token: str = Field(..., description="The site session's refresh token")
    notification_id: int = Field(..., description="The notification to remove from the visitor's list")


@router.post('/notifications/dismiss')
async def dismiss_site_notification(
    request: SiteNotificationDismissRequest,
    db: AsyncSession = Depends(get_cabinet_db),
):
    """Removes one notification from the bell's list -- the "X" on an
    already-read item. A real delete, not a soft dismiss flag: nothing
    else reads SiteNotification rows once they've been shown here, so
    there's no history view this would need to preserve for.
    """
    user_id = await _resolve_site_session_user_id(db, request.refresh_token)
    await db.execute(
        delete(SiteNotification).where(
            SiteNotification.id == request.notification_id, SiteNotification.user_id == user_id
        )
    )
    await db.commit()
    return {'status': 'ok'}


@router.get('/push/vapid-public-key')
async def get_push_vapid_public_key():
    """Public -- this key is meant to be embedded in the site's JS, it is
    not a secret (only the private key, kept server-side, can sign)."""
    return {'public_key': settings.SITE_PUSH_VAPID_PUBLIC_KEY}


class PushSubscriptionKeys(BaseModel):
    p256dh: str
    auth: str


class PushSubscribeRequest(BaseModel):
    refresh_token: str = Field(..., description="The site session's refresh token")
    endpoint: str
    keys: PushSubscriptionKeys
    user_agent: str | None = None


@router.post('/push/subscribe')
async def subscribe_push(
    request: PushSubscribeRequest,
    raw_request: Request,
    db: AsyncSession = Depends(get_cabinet_db),
):
    client_ip = get_client_ip(raw_request)
    if await RateLimitCache.is_ip_rate_limited(client_ip, 'site_push_subscribe', limit=20, window=60, fail_closed=True):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail='Too many requests')

    user_id = await _resolve_site_session_user_id(db, request.refresh_token)

    result = await db.execute(select(PushSubscription).where(PushSubscription.endpoint == request.endpoint))
    existing = result.scalar_one_or_none()
    if existing:
        existing.user_id = user_id
        existing.p256dh_key = request.keys.p256dh
        existing.auth_key = request.keys.auth
        existing.user_agent = request.user_agent
    else:
        db.add(
            PushSubscription(
                user_id=user_id,
                endpoint=request.endpoint,
                p256dh_key=request.keys.p256dh,
                auth_key=request.keys.auth,
                user_agent=request.user_agent,
            )
        )
    await db.commit()
    return {'status': 'ok'}


class PushUnsubscribeRequest(BaseModel):
    refresh_token: str = Field(..., description="The site session's refresh token")
    endpoint: str


@router.post('/push/unsubscribe')
async def unsubscribe_push(
    request: PushUnsubscribeRequest,
    db: AsyncSession = Depends(get_cabinet_db),
):
    user_id = await _resolve_site_session_user_id(db, request.refresh_token)
    await db.execute(
        delete(PushSubscription).where(
            PushSubscription.endpoint == request.endpoint, PushSubscription.user_id == user_id
        )
    )
    await db.commit()
    return {'status': 'ok'}
