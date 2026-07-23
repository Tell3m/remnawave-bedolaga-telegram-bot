"""Public site-trial-claim endpoint for the HotSpot recovery portal.

Lets a website visitor claim the standard trial subscription (see
TRIAL_DURATION_DAYS / TRIAL_TRAFFIC_LIMIT_GB / TRIAL_DEVICE_LIMIT) by email
alone, without going through the Telegram bot or the cabinet UI. Reuses the
exact subscription-creation path the bot's trial button uses
(create_trial_subscription + SubscriptionService.create_remnawave_user) and
the same eligibility gate (User.is_trial_already_used()), so a site-claimed
trial counts against the same one-trial-per-account limit as everywhere
else -- no separate abuse bookkeeping to maintain.

Two-step flow (request-code / verify-code): entering an email alone used to
be enough to activate a trial immediately. A 6-digit emailed code (same
generator/compare pattern as the cabinet's email-change and email-merge OTP
flows, just Redis-keyed by email instead of an authenticated user id) now
gates activation, proving the visitor actually controls the inbox before
any subscription is created.

The same two endpoints also serve as this site's *login* for an email that
already has a subscription -- verify_site_trial_code detects that case and
returns the existing subscription + fresh tokens instead of provisioning a
new trial, rather than punting to the separate magic-link handshake in
auth.py. One code-based flow for the whole site auth surface, instead of
"code for new visitors, link for returning ones".

Multi-signal device abuse check: a visitor who simply clears browser
storage gets a fresh client-generated device_id, silently defeating a
device_id-only check on a second claim from the same physical device. No
single signal is trusted alone -- see _compute_abuse_signal_count -- a
claim is only blocked when at least 2 of {device_id match, FingerprintJS
match, IP-subnet already produced a trial} agree, so clearing just one of
them (the common case) still gets caught by the other two, while a false
positive on any single signal (two different phones sharing a fingerprint,
two strangers sharing a CGNAT IP) never blocks a real visitor on its own.

Intentionally unauthenticated -- mirrors the pattern in site_verification.py.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.cabinet.auth.email_verification import generate_email_change_code
from app.cabinet.auth.site_telegram_link import SITE_TELEGRAM_LINK_TTL_SECONDS, store_site_telegram_link_token
from app.cabinet.auth.site_trial_abuse import get_subnet_trial_user_ids, record_subnet_trial
from app.cabinet.auth.site_trial_otp import (
    SITE_TRIAL_OTP_TTL_SECONDS,
    clear_site_trial_otp,
    get_site_trial_otp,
    store_site_trial_otp,
)
from app.cabinet.services.email_service import email_service
from app.config import settings
from app.database.crud.server_squad import get_random_trial_squad_uuid
from app.database.crud.subscription import create_trial_subscription, get_subscription_by_user_id
from app.database.crud.user import create_user_by_email, get_user_by_id
from app.database.models import CabinetRefreshToken, User, UserStatus
from app.services.disposable_email_service import disposable_email_service
from app.services.remnawave_service import RemnaWaveConfigurationError
from app.services.subscription_service import SubscriptionService
from app.services.trial_activation_service import rollback_trial_subscription_activation
from app.utils.cache import RateLimitCache

from ..auth import get_token_payload
from ..auth.jwt_handler import create_auto_login_token
from ..dependencies import get_cabinet_db
from ..ip_utils import get_client_ip
from .auth import _create_auth_response, _store_refresh_token


logger = structlog.get_logger(__name__)

router = APIRouter(prefix='/public/site-trial', tags=['Cabinet:Public'])

DEVICE_LIMIT_MESSAGE = 'Похоже, с этого устройства уже активировали пробную подписку. Купите подписку 😊'

# Signals must be independently corroborated -- see module docstring.
ABUSE_SIGNAL_BLOCK_THRESHOLD = 2


class SiteTrialRequestCodeRequest(BaseModel):
    email: EmailStr = Field(..., description='Email address')
    device_id: str | None = Field(
        default=None,
        max_length=64,
        description='Client-generated, localStorage-persisted device id (anti-abuse)',
    )
    fingerprint: str | None = Field(
        default=None,
        max_length=64,
        description='FingerprintJS visitorId, recomputed client-side (anti-abuse)',
    )


class SiteTrialRequestCodeResponse(BaseModel):
    status: str = Field(..., description='"code_sent", "already_used" or "device_limit"')
    message: str
    expires_in_minutes: int | None = None


class SiteTrialVerifyCodeRequest(BaseModel):
    email: EmailStr = Field(..., description='Email address')
    code: str = Field(..., min_length=6, max_length=6, pattern=r'^\d{6}$', description='6-digit verification code')
    device_id: str | None = Field(
        default=None,
        max_length=64,
        description='Client-generated, localStorage-persisted device id (anti-abuse)',
    )
    fingerprint: str | None = Field(
        default=None,
        max_length=64,
        description='FingerprintJS visitorId, recomputed client-side (anti-abuse)',
    )


class SiteTrialClaimResponse(BaseModel):
    status: str = Field(
        ...,
        description='"activated", "already_used", "device_limit", "invalid_code" or "expired_code"',
    )
    message: str
    subscription_url: str | None = None
    happ_crypto_link: str | None = None
    expires_at: str | None = None
    traffic_limit_gb: int | None = None
    # Only populated on a returning-user login (see verify_site_trial_code) --
    # a freshly created trial always starts at 0 used / is_trial=True /
    # no tariff, which the frontend already assumes by default.
    traffic_used_gb: float | None = None
    is_trial: bool | None = None
    tariff_name: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None


async def _lookup_user_by_email(db: AsyncSession, email_lower: str) -> User | None:
    result = await db.execute(
        select(User)
        .options(selectinload(User.subscriptions))
        .where(func.lower(User.email) == email_lower, User.status != UserStatus.DELETED.value)
    )
    return result.scalar_one_or_none()


async def _get_or_create_site_trial_user(
    db: AsyncSession, email_lower: str, device_id: str | None, fingerprint: str | None
) -> tuple[User, bool]:
    user = await _lookup_user_by_email(db, email_lower)
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
    if fingerprint:
        user.site_trial_fingerprint = fingerprint
    if device_id or fingerprint:
        await db.commit()
    await db.refresh(user, ['subscriptions'])
    return user, True


async def _find_exact_trial_conflict(
    db: AsyncSession, column, value: str, email_lower: str
) -> User | None:
    """Another (non-deleted) user already tied to this device_id/fingerprint value, if any.

    Used to catch the same physical device claiming the trial again under a
    different email -- ``User.is_trial_already_used()`` alone can't see this
    because a fresh email always produces a fresh, subscription-less User row.
    """
    result = await db.execute(
        select(User)
        .options(selectinload(User.subscriptions))
        .where(
            column == value,
            User.status != UserStatus.DELETED.value,
            func.lower(User.email) != email_lower,
        )
    )
    return result.scalars().first()


async def _compute_abuse_signal_count(
    db: AsyncSession,
    *,
    device_id: str | None,
    fingerprint: str | None,
    client_ip: str,
    email_lower: str,
) -> int:
    """How many of {device_id, fingerprint, IP-subnet} point at an already-used trial.

    Each signal is weak alone (device_id/fingerprint clear on browser reset
    or reinstall; an IP subnet can be shared by many unrelated real
    visitors behind CGNAT/Wi-Fi) -- callers only block once
    ABUSE_SIGNAL_BLOCK_THRESHOLD of them agree.
    """
    count = 0

    if device_id:
        conflict = await _find_exact_trial_conflict(db, User.site_trial_device_id, device_id, email_lower)
        if conflict and conflict.is_trial_already_used():
            count += 1

    if fingerprint:
        conflict = await _find_exact_trial_conflict(db, User.site_trial_fingerprint, fingerprint, email_lower)
        if conflict and conflict.is_trial_already_used():
            count += 1

    subnet_user_ids = await get_subnet_trial_user_ids(client_ip)
    if subnet_user_ids:
        result = await db.execute(
            select(User)
            .options(selectinload(User.subscriptions))
            .where(
                User.id.in_(subnet_user_ids),
                User.status != UserStatus.DELETED.value,
                func.lower(User.email) != email_lower,
            )
        )
        if any(u.is_trial_already_used() for u in result.scalars().all()):
            count += 1

    return count


def _validate_claim_prerequisites(email: str) -> None:
    if disposable_email_service.is_disposable(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Disposable email addresses are not allowed',
        )

    if email.strip().lower() in {e.lower() for e in settings.get_admin_emails()}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='This email address cannot be used')


@router.post('/request-code', response_model=SiteTrialRequestCodeResponse)
async def request_site_trial_code(
    request: SiteTrialRequestCodeRequest,
    raw_request: Request,
    db: AsyncSession = Depends(get_cabinet_db),
):
    """Mail a 6-digit code proving inbox ownership before a trial can be claimed."""
    client_ip = get_client_ip(raw_request)
    if await RateLimitCache.is_ip_rate_limited(
        client_ip, 'site_trial_request_code', limit=5, window=3600, fail_closed=True
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail='Too many requests',
            headers={'Retry-After': '3600'},
        )

    _validate_claim_prerequisites(request.email)
    email_lower = request.email.strip().lower()

    if await RateLimitCache.is_rate_limited(
        email_lower, 'site_trial_request_code_email', limit=3, window=3600, fail_closed=True
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail='Too many requests for this email',
            headers={'Retry-After': '3600'},
        )

    device_id = request.device_id.strip() if request.device_id else None
    fingerprint = request.fingerprint.strip() if request.fingerprint else None

    # Fail fast on device abuse -- no point mailing a code that verification
    # will refuse to honour anyway.
    signal_count = await _compute_abuse_signal_count(
        db, device_id=device_id, fingerprint=fingerprint, client_ip=client_ip, email_lower=email_lower
    )
    if signal_count >= ABUSE_SIGNAL_BLOCK_THRESHOLD:
        return SiteTrialRequestCodeResponse(status='device_limit', message=DEVICE_LIMIT_MESSAGE)

    # An email that already has a subscription isn't claiming a NEW trial --
    # it's proving ownership to log into the existing one (see
    # verify_site_trial_code), so the trial-availability gate below doesn't
    # apply to it even if trials are globally disabled right now.
    existing_user = await _lookup_user_by_email(db, email_lower)
    is_returning_user = bool(existing_user and existing_user.is_trial_already_used())

    if not is_returning_user and (settings.TRIAL_DURATION_DAYS <= 0 or settings.is_trial_disabled_for_user('email')):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Trial is not available')

    code = generate_email_change_code()
    await store_site_trial_otp(email_lower, code, device_id)

    expire_minutes = SITE_TRIAL_OTP_TTL_SECONDS // 60
    sent = await asyncio.to_thread(
        email_service.send_site_trial_code,
        to_email=email_lower,
        code=code,
        expire_minutes=expire_minutes,
        language='ru',
    )
    if not sent:
        await clear_site_trial_otp(email_lower)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Failed to send verification email',
        )

    logger.info('Site trial OTP sent', email=email_lower)
    return SiteTrialRequestCodeResponse(
        status='code_sent',
        message='Verification code sent',
        expires_in_minutes=expire_minutes,
    )


@router.post('/verify-code', response_model=SiteTrialClaimResponse)
async def verify_site_trial_code(
    request: SiteTrialVerifyCodeRequest,
    raw_request: Request,
    db: AsyncSession = Depends(get_cabinet_db),
):
    """Verify the emailed code and, if it matches, activate the trial subscription."""
    client_ip = get_client_ip(raw_request)
    if await RateLimitCache.is_ip_rate_limited(
        client_ip, 'site_trial_verify_code', limit=8, window=600, fail_closed=True
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail='Too many requests',
            headers={'Retry-After': '600'},
        )

    email_lower = request.email.strip().lower()

    if await RateLimitCache.is_rate_limited(
        email_lower, 'site_trial_verify_code_email', limit=5, window=900, fail_closed=True
    ):
        # Burn the pending code so a brute-force run can't keep grinding it --
        # same lockout idiom as the cabinet's email-change/merge OTP flows.
        await clear_site_trial_otp(email_lower)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail='Too many attempts, request a new code',
            headers={'Retry-After': '900'},
        )

    otp = await get_site_trial_otp(email_lower)
    if not otp:
        return SiteTrialClaimResponse(
            status='expired_code',
            message='Code expired or was never requested, please request a new one',
        )

    if not hmac.compare_digest(str(otp.get('code', '')), request.code):
        return SiteTrialClaimResponse(status='invalid_code', message='Invalid verification code')

    device_id = (request.device_id.strip() if request.device_id else None) or otp.get('device_id')
    fingerprint = request.fingerprint.strip() if request.fingerprint else None
    await clear_site_trial_otp(email_lower)

    # Re-check abuse signals at activation time too (defense in depth
    # against a second tab/device racing the same email through
    # request-code, or a fingerprint that only became available after it).
    signal_count = await _compute_abuse_signal_count(
        db, device_id=device_id, fingerprint=fingerprint, client_ip=client_ip, email_lower=email_lower
    )
    if signal_count >= ABUSE_SIGNAL_BLOCK_THRESHOLD:
        return SiteTrialClaimResponse(status='device_limit', message=DEVICE_LIMIT_MESSAGE)

    user, _created = await _get_or_create_site_trial_user(db, email_lower, device_id, fingerprint)

    if user.status != UserStatus.ACTIVE.value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Account is not active')

    if user.is_trial_already_used():
        # Not a new claim -- the code just proved this visitor owns an
        # email that already has a subscription (trial or paid). Log them
        # into it instead of the old separate magic-link handshake, so the
        # whole site auth surface is a single code-based flow.
        subscription = await get_subscription_by_user_id(db, user.id)
        if not subscription:
            return SiteTrialClaimResponse(status='already_used', message='Trial already used for this email')

        logger.info('Site trial login confirmed', user_id=user.id, email=email_lower)
        auth_response = await _create_auth_response(user, db)
        await _store_refresh_token(db, user.id, auth_response.refresh_token, device_info='site_trial_login')

        return SiteTrialClaimResponse(
            status='activated',
            message='Login confirmed',
            subscription_url=subscription.subscription_url,
            happ_crypto_link=subscription.subscription_crypto_link,
            expires_at=subscription.end_date.isoformat() if subscription.end_date else None,
            traffic_limit_gb=subscription.traffic_limit_gb,
            traffic_used_gb=subscription.traffic_used_gb,
            is_trial=subscription.is_trial,
            tariff_name=subscription.tariff.name if subscription.tariff else None,
            access_token=auth_response.access_token,
            refresh_token=auth_response.refresh_token,
            expires_in=auth_response.expires_in,
        )

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
    await record_subnet_trial(client_ip, user.id)

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


class SiteCabinetHandoffRequest(BaseModel):
    refresh_token: str = Field(..., description="The site session's refresh token (from request/verify-code)")


class SiteCabinetHandoffResponse(BaseModel):
    auto_login_url: str


@router.post('/cabinet-handoff', response_model=SiteCabinetHandoffResponse)
async def site_cabinet_handoff(
    request: SiteCabinetHandoffRequest,
    raw_request: Request,
    db: AsyncSession = Depends(get_cabinet_db),
):
    """Turn an already-verified site session into a one-click cabinet login.

    verify_site_trial_code already issues real cabinet refresh tokens (same
    _create_auth_response the cabinet's own login uses) -- this just mints
    the SAME one-time auto_login JWT the magic-link email already uses (see
    request_magic_link / create_auto_login_token), so the site's "Кабинет"
    button can drop a visitor straight into the cabinet at
    {CABINET_URL}/auto-login?token=... without asking for email/code again,
    any time later, as long as the stored refresh token is still valid.

    Deliberately does not special-case admin accounts here -- /login/auto
    itself already rejects them (guest-purchase auto-login security
    boundary, see auto_login()), so that protection carries over for free.
    """
    client_ip = get_client_ip(raw_request)
    if await RateLimitCache.is_ip_rate_limited(
        client_ip, 'site_trial_cabinet_handoff', limit=10, window=60, fail_closed=True
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail='Too many requests',
            headers={'Retry-After': '60'},
        )

    payload = get_token_payload(request.refresh_token, expected_type='refresh')
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid or expired session')

    try:
        user_id = int(payload.get('sub'))
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token payload') from error

    token_hash = hashlib.sha256(request.refresh_token.encode()).hexdigest()
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

    auto_login_token = create_auto_login_token(user.id, ttl_hours=1)
    return SiteCabinetHandoffResponse(auto_login_url=f'{settings.CABINET_URL}/auto-login?token={auto_login_token}')


class SiteTelegramLinkRequest(BaseModel):
    refresh_token: str = Field(..., description="The site session's refresh token (from request/verify-code)")


class SiteTelegramLinkResponse(BaseModel):
    start_param: str
    expires_in_minutes: int


@router.post('/telegram-link-token', response_model=SiteTelegramLinkResponse)
async def create_site_telegram_link_token(
    request: SiteTelegramLinkRequest,
    raw_request: Request,
    db: AsyncSession = Depends(get_cabinet_db),
):
    """Mint a one-time /start payload proving this Telegram session's owner
    already verified an email on the site.

    Same refresh-token validation as /cabinet-handoff (this IS the site's
    session, not a new credential) -- see that endpoint's docstring. The
    token itself (site_telegram_link.py, Redis, 30 min TTL) is consumed
    bot-side in app/handlers/start.py to either attach telegram_id to this
    email's existing User row (brand-new bot user) or offer a merge
    confirmation (bot user already exists under a different account).
    """
    client_ip = get_client_ip(raw_request)
    if await RateLimitCache.is_ip_rate_limited(
        client_ip, 'site_trial_telegram_link', limit=10, window=60, fail_closed=True
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail='Too many requests',
            headers={'Retry-After': '60'},
        )

    payload = get_token_payload(request.refresh_token, expected_type='refresh')
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid or expired session')

    try:
        user_id = int(payload.get('sub'))
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token payload') from error

    token_hash = hashlib.sha256(request.refresh_token.encode()).hexdigest()
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
    if not user or user.status != UserStatus.ACTIVE.value or not user.email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Account not active')

    # URL-safe (A-Za-z0-9_-) and well under Telegram's 64-char /start payload
    # limit even with the "link_" prefix added client-side.
    token = secrets.token_urlsafe(24)
    await store_site_telegram_link_token(token, user.id, user.email)

    return SiteTelegramLinkResponse(
        start_param=f'link_{token}',
        expires_in_minutes=SITE_TELEGRAM_LINK_TTL_SECONDS // 60,
    )
