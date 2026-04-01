from ..env import get_env

REDIS_URL = get_env(
    "REDIS_URL",
    default="redis://localhost:6379/0",
)