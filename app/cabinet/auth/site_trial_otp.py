"""Redis-backed OTP for the public, unauthenticated site-trial-claim flow.

Mirrors the email-merge OTP pattern in ``merge_service.py``, but keyed by
the claimed email address itself -- this flow has no authenticated user id
to key off of, since entering an email is the entirety of a visitor's
"identity" before the trial is granted.
"""

from datetime import UTC, datetime
from typing import Any

from app.utils.cache import cache, cache_key


SITE_TRIAL_OTP_PREFIX = 'site_trial_otp'
SITE_TRIAL_OTP_TTL_SECONDS = 600  # 10 minutes


async def store_site_trial_otp(email_lower: str, code: str, device_id: str | None) -> None:
    """Store a pending site-trial code for the email (overwrites any prior)."""
    await cache.set(
        cache_key(SITE_TRIAL_OTP_PREFIX, email_lower),
        {
            'code': code,
            'device_id': device_id,
            'created_at': datetime.now(UTC).isoformat(),
        },
        expire=SITE_TRIAL_OTP_TTL_SECONDS,
    )


async def get_site_trial_otp(email_lower: str) -> dict[str, Any] | None:
    """Read the pending site-trial code without consuming it."""
    data: Any = await cache.get(cache_key(SITE_TRIAL_OTP_PREFIX, email_lower))
    return data if isinstance(data, dict) else None


async def clear_site_trial_otp(email_lower: str) -> None:
    """Drop the pending site-trial code."""
    await cache.getdel(cache_key(SITE_TRIAL_OTP_PREFIX, email_lower))
