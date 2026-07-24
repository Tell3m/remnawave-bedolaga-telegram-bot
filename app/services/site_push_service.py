"""Delivery for the recovery-portal site's notification bell + Web Push.

Two independent things happen for every notification pushed through here:
1. A SiteNotification row is written -- this is what the bell/notification
   center on the site reads (see app/cabinet/routes/site_notifications.py).
2. A Web Push message is sent to every PushSubscription the user has
   registered a browser for, if any -- this is what makes the OS show a
   lock-screen/notification-center alert even with the site closed. A
   dead subscription (browser uninstalled, permission revoked -- the push
   service replies 404/410) is deleted so it stops being retried.

Both steps are best-effort and never raise -- a failure here must never
break the caller's actual business logic (e.g. don't fail a subscription
renewal because a push send timed out).
"""

from __future__ import annotations

import asyncio
import json

import structlog
from pywebpush import WebPushException, webpush
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database.database import AsyncSessionLocal
from app.database.models import PushSubscription, SiteNotification


logger = structlog.get_logger(__name__)


async def deliver_site_notification(
    *,
    user_id: int,
    notification_type: str,
    title: str,
    body: str,
    deep_link: str | None = None,
) -> None:
    """Write the bell entry and fan out a Web Push to this user's browsers.

    Opens its own short-lived DB session rather than taking one from the
    caller -- this is called from many different places (the unified
    notification pipe, the traffic-warning cron check, admin broadcasts),
    several of which are mid-transaction on their own session already, and
    this side effect must never be entangled with (or roll back with) the
    caller's actual business transaction.
    """
    async with AsyncSessionLocal() as db:
        try:
            db.add(
                SiteNotification(
                    user_id=user_id,
                    type=notification_type,
                    title=title,
                    body=body,
                    deep_link=deep_link,
                )
            )
            await db.commit()
        except Exception as e:
            logger.warning('Failed to write site notification', user_id=user_id, type=notification_type, error=e)
            await db.rollback()

        await _send_web_push(db, user_id=user_id, title=title, body=body, deep_link=deep_link)


async def _send_web_push(
    db: AsyncSession,
    *,
    user_id: int,
    title: str,
    body: str,
    deep_link: str | None,
) -> None:
    if not settings.SITE_PUSH_VAPID_PRIVATE_KEY:
        return

    result = await db.execute(select(PushSubscription).where(PushSubscription.user_id == user_id))
    subscriptions = result.scalars().all()
    if not subscriptions:
        return

    payload = json.dumps({'title': title, 'body': body, 'deep_link': deep_link})
    dead_ids: list[int] = []

    for sub in subscriptions:
        try:
            await asyncio.to_thread(
                webpush,
                subscription_info={
                    'endpoint': sub.endpoint,
                    'keys': {'p256dh': sub.p256dh_key, 'auth': sub.auth_key},
                },
                data=payload,
                vapid_private_key=settings.SITE_PUSH_VAPID_PRIVATE_KEY,
                vapid_claims={'sub': settings.SITE_PUSH_VAPID_SUBJECT},
            )
        except WebPushException as e:
            status_code = getattr(e.response, 'status_code', None)
            if status_code in (404, 410):
                dead_ids.append(sub.id)
            else:
                logger.warning('Web push send failed', user_id=user_id, subscription_id=sub.id, error=str(e))
        except Exception as e:
            logger.warning('Unexpected error sending web push', user_id=user_id, subscription_id=sub.id, error=e)

    if dead_ids:
        try:
            await db.execute(delete(PushSubscription).where(PushSubscription.id.in_(dead_ids)))
            await db.commit()
        except Exception as e:
            logger.warning('Failed to clean up dead push subscriptions', error=e)
            await db.rollback()
