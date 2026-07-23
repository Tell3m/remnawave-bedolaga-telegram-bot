"""Redis-backed handoff token: site email session -> Telegram bot linking.

A visitor who verified their email on the recovery-portal site (see
site_trial.py's request-code/verify-code) already proved they own that
inbox. When they then tap "Открыть Telegram", the site mints one of these
tokens and passes it as the bot's /start deep-link payload
(https://t.me/<bot>?start=link_<token>) so the bot can recognize "this
Telegram session belongs to an already-verified email" and offer to
attach/merge instead of silently creating a second, disconnected account.

Short-lived and single-use, same idiom as the email-merge OTP in
merge_service.py -- the token itself is the proof, nothing more needs to
be re-verified bot-side.
"""

from datetime import UTC, datetime
from typing import Any

from app.utils.cache import cache, cache_key


SITE_TELEGRAM_LINK_PREFIX = 'site_telegram_link'
SITE_TELEGRAM_LINK_TTL_SECONDS = 1800  # 30 minutes -- matches account_merge tokens


async def store_site_telegram_link_token(token: str, user_id: int, email: str) -> None:
    await cache.set(
        cache_key(SITE_TELEGRAM_LINK_PREFIX, token),
        {'user_id': user_id, 'email': email, 'created_at': datetime.now(UTC).isoformat()},
        expire=SITE_TELEGRAM_LINK_TTL_SECONDS,
    )


async def get_site_telegram_link_token(token: str) -> dict[str, Any] | None:
    """Read without consuming -- callers decide when the token is actually spent."""
    data: Any = await cache.get(cache_key(SITE_TELEGRAM_LINK_PREFIX, token))
    return data if isinstance(data, dict) else None


async def clear_site_telegram_link_token(token: str) -> None:
    await cache.getdel(cache_key(SITE_TELEGRAM_LINK_PREFIX, token))
