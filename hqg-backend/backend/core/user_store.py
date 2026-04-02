import json
import logging
import os

from backend.core.auth import get_password_hash
from backend.core.redis import redis_client


logger = logging.getLogger(__name__)


def _user_key(username: str) -> str:
    return f"users:{username}"


async def get_user(username: str) -> dict | None:
    raw_user = await redis_client.get(_user_key(username))
    if not raw_user:
        return None
    return json.loads(raw_user)


async def create_user(username: str, password: str, role: str) -> dict:
    user = {
        "username": username,
        "password_hash": get_password_hash(password),
        "role": role,
    }
    await redis_client.set(_user_key(username), json.dumps(user))
    return user


async def update_password(username: str, new_password: str) -> bool:
    """Update an existing user's password. Returns False if user not found."""
    user = await get_user(username)
    if not user:
        return False
    user["password_hash"] = get_password_hash(new_password)
    await redis_client.set(_user_key(username), json.dumps(user))
    return True


async def seed_admin_user() -> None:
    async for _ in redis_client.scan_iter(match="users:*", count=1):
        return

    # Credentials are read from environment variables so they can be set
    # securely at deploy time without hardcoding them in source.
    admin_username = os.environ.get("HQG_ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("HQG_ADMIN_PASSWORD", "")

    if not admin_password:
        # Refuse to start with a blank password — generate a random one and
        # log it once so the operator can retrieve it from startup logs.
        import secrets as _secrets
        admin_password = _secrets.token_urlsafe(16)
        logger.warning(
            "HQG_ADMIN_PASSWORD not set — generated random admin password: %s  "
            "Set HQG_ADMIN_PASSWORD in your .env / environment to persist it.",
            admin_password,
        )

    await create_user(username=admin_username, password=admin_password, role="admin")
    logger.info("Seeded admin user %r — change credentials via HQG_ADMIN_PASSWORD env var.", admin_username)