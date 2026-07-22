"""Public site-trial-claim endpoint for the HotSpot recovery portal.

Lets a website visitor claim the standard trial subscription (see
TRIAL_DURATION_DAYS / TRIAL_TRAFFIC_LIMIT_GB / TRIAL_DEVICE_LIMIT) by email
alone, without going through the Telegram bot or the cabinet UI. Reuses the
exact subscription-creation path the bot's trial button uses
(create_trial_subscription + SubscriptionService.create_remnawave_user) and
the same eligibility gate (User.is_trial_already_used()), so a site-claimed
trial counts against the same one-trial-per-account limit as everywhere
else — no separate abuse bookkeeping to maintain.

Intentionally unauthenticated — mirrors the pattern in site_verification.py.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.database.crud.server_squad import get_random_trial_squad_uuid
from app.database.crud.subscription import create_trial_subscription
from app.database.crud.user import create_user_by_email
from app.database.models import User, UserStatus
from app.services.disposable_email_service import disposable_email_service
from app.services.remnawave_service import RemnaWaveConfigurationError
from app.services.subscription_service import SubscriptionService
from app.services.trial_activation_service import rollback_trial_subscription_activation
from app.utils.cache import RateLimitCache

from ..dependencies import get_cabinet_db
from ..ip_utils import get_client_ip
from .auth import _create_auth_response, _store_refresh_token


logger = structlog.get_logger(__name__)

router = APIRouter(prefix='/public/site-trial', tags=['Cabinet:Public'])
class SiteTrialClaimRequest(BaseModel):
    email: EmailStr = Field(..., description='Email address')
    device_id: str | None = Field(
        default=None,
        max_length=64,
        description='Client-generated, localStorage-persisted device id (anti-abuse)',
    )


class SiteTrialClaimResponse(BaseModel):
    status: str = Field(..., description='"activated", "already_used" or "device_limit"')
    message: str
    subscription_url: str | None = None
    happ_crypto_link: str | None = None
    expires_at: str | None = None
    traffic_limit_gb: int | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None


async def _get_or_create_site_trial_user(
    db: AsyncSession, email_lower: str, device_id: str | None
) -> tuple[User, bool]:
    result = await db.execute(
        select(User)
        .options(selectinload(User.subscriptions))
        .where(func.lower(User.email) == email_lower, User.status != UserStatus.DELETED.value)
    )
    user = result.scalar_one_or_none()
    if user:
        return user, False

    user = await create_user_by_email(
        db=db,
        email=email_lower,
        password_hash=None,
        first_name=None,
        language='ru',
    )
    if device_id:
        user.site_trial_device_id = device_id
        await db.commit()
    await db.refresh(user, ['subscriptions'])
    return user, True


async def _find_device_trial_conflict(db: AsyncSession, device_id: str, email_lower: str) -> User | None:
    """Another (non-deleted) user already tied to this device id, if any.

    Used to catch the same physical device claiming the trial again under a
    different email -- ``User.is_trial_already_used()`` alone can't see this
    because a fresh email always produces a fresh, subscription-less User row.
    """
    result = await db.execute(
        select(User)
        .options(selectinload(User.subscriptions))
        .where(
            User.site_trial_device_id == device_id,
            User.status != UserStatus.DELETED.value,
            func.lower(User.email) != email_lower,
        )
    )
    return result.scalars().first()
@router.post('/claim', response_model=SiteTrialClaimResponse)
async def claim_site_trial(
    request: SiteTrialClaimRequest,
    raw_request: Request,
    db: AsyncSession = Depends(get_cabinet_db),
):
    """Claim the standard trial subscription for an email, no bot/cabinet needed."""
    client_ip = get_client_ip(raw_request)
    if await RateLimitCache.is_ip_rate_limited(client_ip, 'site_trial_claim', limit=5, window=3600, fail_closed=True):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail='Too many requests',
            headers={'Retry-After': '3600'},
        )

    if disposable_email_service.is_disposable(request.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Disposable email addresses are not allowed',
        )

    email_lower = request.email.strip().lower()
    if email_lower in {e.lower() for e in settings.get_admin_emails()}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='This email address cannot be used')

    if settings.TRIAL_DURATION_DAYS <= 0 or settings.is_trial_disabled_for_user('email'):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Trial is not available')

    device_id = request.device_id.strip() if request.device_id else None

    if device_id:
        device_conflict = await _find_device_trial_conflict(db, device_id, email_lower)
        if device_conflict and device_conflict.is_trial_already_used():
            return SiteTrialClaimResponse(
                status='device_limit',
                message='Trial already claimed on this device',
            )

    user, _created = await _get_or_create_site_trial_user(db, email_lower, device_id)

    if user.status != UserStatus.ACTIVE.value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Account is not active')

    if user.is_trial_already_used():
        return SiteTrialClaimResponse(status='already_used', message='Trial already used for this email')
    trial_squad_uuid = await get_random_trial_squad_uuid(db)
    trial_squads = [trial_squad_uuid] if trial_squad_uuid else []

    subscription = await create_trial_subscription(
        db,
        user.id,
        connected_squads=trial_squads,
    )
    await db.refresh(user)

    subscription_service = SubscriptionService()
    try:
        remnawave_user = await subscription_service.create_remnawave_user(db, subscription)
    except RemnaWaveConfigurationError as error:
        logger.error('RemnaWave update skipped due to configuration error (site trial)', error=error)
        await rollback_trial_subscription_activation(db, subscription)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Trial provisioning temporarily unavailable',
        ) from error
    except Exception as error:
        logger.error('Failed to create RemnaWave user for site trial', user_id=user.id, error=error)
        await rollback_trial_subscription_activation(db, subscription)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Trial provisioning temporarily unavailable',
        ) from error

    if not remnawave_user:
        await rollback_trial_subscription_activation(db, subscription)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Trial provisioning temporarily unavailable',
        )

    await db.refresh(subscription)
    logger.info('Site trial activated', user_id=user.id, email=email_lower, subscription_id=subscription.id)

    # Issue a token pair so the site can silently refresh this visitor's real
    # subscription status on later visits (see /auth/refresh) instead of
    # caching the claim-time snapshot forever.
    auth_response = await _create_auth_response(user, db)
    await _store_refresh_token(db, user.id, auth_response.refresh_token, device_info='site_trial')

    return SiteTrialClaimResponse(
        status='activated',
        message='Trial activated',
        subscription_url=subscription.subscription_url,
        happ_crypto_link=subscription.subscription_crypto_link,
        expires_at=subscription.end_date.isoformat() if subscription.end_date else None,
        traffic_limit_gb=subscription.traffic_limit_gb,
        access_token=auth_response.access_token,
        refresh_token=auth_response.refresh_token,
        expires_in=auth_response.expires_in,
    )
