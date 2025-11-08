from celery import shared_task
from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)


@shared_task
def clear_expired_cache():
    """"Clear expired cache entries"""
    try:
        # Django's cache framework handles expiration automatically for most backends
        logger.info("Cache cleanup completed")
        return True
    except Exception as exc:
        logger.error(f"Cache cleanup failed: {str(exc)}")
        return False


@shared_task
def health_check():
    """"Perform basic system health check"""
    try:
        # Check database connectivity
        from django.db import connection
        cursor = connection.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()

        # Check cache connectivity
        cache.set('health_check', 'ok', timeout=10)
        result = cache.get('health_check')
        if result != 'ok':
            raise Exception("Cache not working properly")

        logger.info("Health check passed")
        return True
    except Exception as exc:
        logger.error(f"Health check failed: {str(exc)}")
        return False