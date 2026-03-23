import json
import logging

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


async def seed_admin_user() -> None:
    async for _ in redis_client.scan_iter(match="users:*", count=1):
        return

    await create_user(username="admin", password="admin123", role="admin")
    logger.warning("Seeded default admin user with username 'admin' and password 'admin123'; change these credentials immediately")