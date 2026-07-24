"""Redis-backed challenge storage for the site's WebAuthn (Face ID) flow.

WebAuthn's register/login ceremonies are two-step: mint a challenge here,
hand it to the browser's navigator.credentials.create()/get(), then verify
whatever comes back against the exact same challenge. Mirrors the
site_trial_otp.py pattern (a short-lived Redis token, not a DB row -- these
are single-use and expire in minutes, not the kind of thing worth a table).
"""

from typing import Any

from app.utils.cache import cache, cache_key


WEBAUTHN_REGISTER_PREFIX = 'webauthn_register_challenge'
WEBAUTHN_LOGIN_PREFIX = 'webauthn_login_challenge'
WEBAUTHN_CHALLENGE_TTL_SECONDS = 300  # 5 minutes -- plenty for a biometric prompt


async def store_registration_challenge(challenge_token: str, user_id: int, challenge: str) -> None:
    await cache.set(
        cache_key(WEBAUTHN_REGISTER_PREFIX, challenge_token),
        {'user_id': user_id, 'challenge': challenge},
        expire=WEBAUTHN_CHALLENGE_TTL_SECONDS,
    )


async def get_registration_challenge(challenge_token: str) -> dict[str, Any] | None:
    data: Any = await cache.get(cache_key(WEBAUTHN_REGISTER_PREFIX, challenge_token))
    return data if isinstance(data, dict) else None


async def clear_registration_challenge(challenge_token: str) -> None:
    await cache.getdel(cache_key(WEBAUTHN_REGISTER_PREFIX, challenge_token))


async def store_login_challenge(challenge_token: str, challenge: str) -> None:
    # No user_id yet -- login is usernameless/discoverable, the credential
    # in the assertion is what tells us who's logging in, not this challenge.
    await cache.set(
        cache_key(WEBAUTHN_LOGIN_PREFIX, challenge_token),
        {'challenge': challenge},
        expire=WEBAUTHN_CHALLENGE_TTL_SECONDS,
    )


async def get_login_challenge(challenge_token: str) -> dict[str, Any] | None:
    data: Any = await cache.get(cache_key(WEBAUTHN_LOGIN_PREFIX, challenge_token))
    return data if isinstance(data, dict) else None


async def clear_login_challenge(challenge_token: str) -> None:
    await cache.getdel(cache_key(WEBAUTHN_LOGIN_PREFIX, challenge_token))
