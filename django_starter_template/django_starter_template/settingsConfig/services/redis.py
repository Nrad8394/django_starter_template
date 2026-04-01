"""
Redis Connection Configuration
================================

Exposes a single ``REDIS_URL`` constant that provides the default Redis
connection string used by both the cache backend and the Celery broker.

Design notes:
- A single ``REDIS_URL`` is intentionally kept as the shared default so
  that other modules (``performance.py``, ``celery.py``) can import it
  without duplicating the ``get_env`` call. Environment- or service-
  specific overrides are applied in the consuming module rather than here
  (e.g. ``celery.py`` exposes separate ``CELERY_BROKER_URL`` and
  ``CELERY_RESULT_BACKEND`` env vars that default to different Redis DB
  numbers).
- Set ``REDIS_URL`` to a Unix socket path (``redis+socket:///…``) or a
  Sentinel/Cluster URL when running in high-availability mode.
- The default ``redis://localhost:6379/0`` is only suitable for local
  development. Production should always supply ``REDIS_URL`` via the
  environment/secrets manager.

Environment variable:
  ``REDIS_URL``  (default: ``redis://localhost:6379/0``)

Reference: https://redis-py.readthedocs.io/
"""

from ..env import get_env

REDIS_URL = get_env(
    "REDIS_URL",
    default="redis://localhost:6379/0",
)