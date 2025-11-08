"""
Performance and Caching Configuration for the Application
==========================================================

This module contains performance-related configurations including:
- Redis configuration and caching
- Performance timeouts and limits
- Database query optimization settings
"""

from .storage import REDIS_URL

# Cache Configuration
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': REDIS_URL,
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'TIMEOUT': 300,  # 5 minutes default
    }
}

# Performance Settings
DB_QUERY_TIMEOUT = 30
API_TIMEOUT = 30
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB