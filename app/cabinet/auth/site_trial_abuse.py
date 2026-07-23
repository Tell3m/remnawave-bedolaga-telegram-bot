"""IP-subnet volume tracking for the site-trial multi-signal abuse check.

An IP address alone is too noisy to gate on directly -- CGNAT and shared
Wi-Fi mean many unrelated real visitors can share one /24, so this only
answers "has this subnet already produced a completed trial claim
recently", never "is this the same person". See
site_trial.py's _compute_abuse_signal_count, which only blocks when this
signal agrees with a device_id or fingerprint match, never on its own.
"""

from ipaddress import ip_address

from app.utils.cache import cache, cache_key


SITE_TRIAL_SUBNET_PREFIX = 'site_trial_subnet'
SITE_TRIAL_SUBNET_TTL_SECONDS = 30 * 24 * 3600  # 30 days, refreshed on each add


def subnet_key_for_ip(ip: str) -> str | None:
    """/24 for IPv4, /64 for IPv6. None for anything unparseable."""
    try:
        addr = ip_address(ip)
    except ValueError:
        return None
    if addr.version == 4:
        octets = str(addr).split('.')
        return f'{octets[0]}.{octets[1]}.{octets[2]}.0/24'
    prefix = addr.exploded.split(':')[:4]
    return ':'.join(prefix) + '::/64'


async def record_subnet_trial(ip: str, user_id: int) -> None:
    """Record that `user_id` completed a trial claim from `ip`'s subnet."""
    subnet = subnet_key_for_ip(ip)
    if not subnet:
        return
    key = cache_key(SITE_TRIAL_SUBNET_PREFIX, subnet)
    await cache.redis_client.sadd(key, user_id)
    await cache.redis_client.expire(key, SITE_TRIAL_SUBNET_TTL_SECONDS)


async def get_subnet_trial_user_ids(ip: str) -> set[int]:
    """User ids that previously completed a trial claim from `ip`'s subnet."""
    subnet = subnet_key_for_ip(ip)
    if not subnet:
        return set()
    key = cache_key(SITE_TRIAL_SUBNET_PREFIX, subnet)
    if not cache._connected or cache.redis_client is None:
        return set()
    members = await cache.redis_client.smembers(key)
    result = set()
    for m in members:
        try:
            result.add(int(m))
        except (TypeError, ValueError):
            continue
    return result
