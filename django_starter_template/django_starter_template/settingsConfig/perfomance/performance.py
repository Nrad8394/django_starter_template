"""
Performance and Caching Configuration
======================================

This module contains performance-related configurations including:
- Cache backend configuration
- Performance timeouts and limits
- Database query optimization settings

Note: Cache backends are further overridden in environment-specific modules
(development.py, production.py, test.py).
"""
from ..base import REDIS_URL

# Cache timeout defaults
DEFAULT_CACHE_TIMEOUT = 300  # 5 minutes

# Performance Settings (timeouts and limits - consistent across environments)
DB_QUERY_TIMEOUT = 30
API_TIMEOUT = 30
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": REDIS_URL,
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        },
        "TIMEOUT": 300,  # 5 minutes default
    }
}
