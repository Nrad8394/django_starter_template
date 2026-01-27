"""
Production Settings
===================

This module overrides base settings for production deployment.

IMPORTANT: All sensitive configuration must be provided via environment variables:
  - SECRET_KEY
  - POSTGRES_* (database credentials)
  - EMAIL_* (mail server credentials)
  - CORS_ALLOWED_ORIGINS
  - CSRF_TRUSTED_ORIGINS
  - CELERY_BROKER_URL
  - CELERY_RESULT_BACKEND
  - REDIS_CACHE_URL

Never hardcode credentials or secrets in this file.
"""

from .base import *
from copy import deepcopy
from decouple import config

# =============================================================================
# DEBUG AND SECURITY
# =============================================================================
DEBUG = config("DJANGO_DEBUG", default=False, cast=bool)

# Ensure SECRET_KEY is set in production
if DEBUG is False and SECRET_KEY == "django-insecure-dev-only-change-in-production":
    raise ValueError(
        "SECRET_KEY must be set in environment for production! "
        "Set the SECRET_KEY environment variable."
    )

# =============================================================================
# DATABASE - PostgreSQL with PgBouncer
# =============================================================================
# Use PostgreSQL in production with connection pooling (PgBouncer)
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": config("POSTGRES_DB", default="django_starter_template_db"),
        "USER": config("POSTGRES_USER", default="postgres"),
        "PASSWORD": config("POSTGRES_PASSWORD", default=""),
        "HOST": config("DB_HOST", default="pgbouncer"),
        "PORT": config("DB_PORT", default="6432", cast=int),
        "CONN_MAX_AGE": 0,  # Disable persistent connections with PgBouncer
        "CONN_HEALTH_CHECKS": True,
    }
}

# =============================================================================
# SECURITY HEADERS
# =============================================================================
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

# HSTS - only enable if serving HTTPS
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Note: Set to True only if serving HTTPS
SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", default=False, cast=bool)
SESSION_COOKIE_SECURE = config("SESSION_COOKIE_SECURE", default=False, cast=bool)
CSRF_COOKIE_SECURE = config("CSRF_COOKIE_SECURE", default=False, cast=bool)
# Proxy settings for Nginx
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = False  # Allow JS access to CSRF token
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

# =============================================================================
# CORS
# =============================================================================
CORS_ALLOWED_ORIGINS = config(
    "CORS_ALLOWED_ORIGINS",
    default="http://localhost:3000",
    cast=lambda v: [s.strip() for s in v.split(",")],
)

# =============================================================================
# CSRF
# =============================================================================
CSRF_TRUSTED_ORIGINS = config(
    "CSRF_TRUSTED_ORIGINS",
    default="http://localhost:3000",
    cast=lambda v: [s.strip() for s in v.split(",")],
)

# =============================================================================
# EMAIL - SMTP Configuration
# =============================================================================
# Override console backend with SMTP for production
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = config("EMAIL_HOST", default="smtp.gmail.com")
EMAIL_PORT = config("EMAIL_PORT", default=587, cast=int)
EMAIL_USE_TLS = config("EMAIL_USE_TLS", default=True, cast=bool)
EMAIL_HOST_USER = config("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD", default="")
DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL", default="noreply@example.com")

# =============================================================================
# CELERY - Production Configuration
# =============================================================================
CELERY_TASK_ALWAYS_EAGER = False
CELERY_TASK_EAGER_PROPAGATES = False
CELERY_BROKER_URL = config("CELERY_BROKER_URL", default="redis://redis-master:6379/0")
CELERY_RESULT_BACKEND = config(
    "CELERY_RESULT_BACKEND", default="redis://redis-master:6379/1"
)

# =============================================================================
# CACHING - Redis
# =============================================================================
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": config("REDIS_CACHE_URL", default="redis://redis-master:6379/2"),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        },
    }
}

# =============================================================================
# SESSION
# =============================================================================
SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"

# =============================================================================
# LOGGING - Production Logging
# =============================================================================
LOGGING = deepcopy(LOGGING)
LOGGING["handlers"]["django_file"]["filename"] = "/app/logs/django.log"
LOGGING["handlers"]["django_file"]["formatter"] = "json"
LOGGING["handlers"]["celery_file"]["filename"] = "/app/logs/celery.log"
LOGGING["handlers"]["celery_file"]["formatter"] = "json"
LOGGING["root"]["level"] = config("LOG_LEVEL", default="WARNING")
LOGGING["loggers"]["apps"]["level"] = config("DJANGO_LOG_LEVEL", default="INFO")

# =============================================================================
# MONITORING
# =============================================================================
PROMETHEUS_METRICS_ENABLED = config(
    "PROMETHEUS_METRICS_ENABLED", default=True, cast=bool
)

# =============================================================================
# ERROR TRACKING - Sentry (Optional)
# =============================================================================
SENTRY_DSN = config("SENTRY_DSN", default="")
if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration

    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[DjangoIntegration()],
        traces_sample_rate=0.1,
        send_default_pii=False,
        environment=config("ENVIRONMENT", default="production"),
    )

    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    from sentry_sdk.integrations.celery import CeleryIntegration

    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(),
            CeleryIntegration(),
        ],
        traces_sample_rate=0.1,
        send_default_pii=False,
        attach_stacktrace=True,
    )
