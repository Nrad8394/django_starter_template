from .base import *
import os

DEBUG = config('DJANGO_DEBUG', default=False, cast=bool)

# Production database settings - use individual variables as set in environment
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('POSTGRES_DB', default='agex_db'),
        'USER': config('POSTGRES_USER', default='postgres'),
        'PASSWORD': config('POSTGRES_PASSWORD', default='password'),
        'HOST': config('DB_HOST', default='pgbouncer'),
        'PORT': config('DB_PORT', default='6432'),
        'CONN_MAX_AGE': 0,  # Disable persistent connections when using PgBouncer
        'CONN_HEALTH_CHECKS': True,
    }
}

# Security settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_PROXY_SSL_HEADER = None  # Disable for HTTP deployment

# Force HTTPS - disabled for HTTP deployment
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False  # Allow HTTP for development/production HTTP
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SECURE = False  # Allow HTTP for development/production HTTP
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript access to CSRF token

# CORS for production
CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS',
    default='http://localhost:3000,http://127.0.0.1:3000,https://agex.signox.great-site.net,http://102.207.222.11',
    cast=lambda v: [s.strip() for s in v.split(',')]
)

# CSRF for production - must include domains that serve the frontend
CSRF_TRUSTED_ORIGINS = config(
    'CSRF_TRUSTED_ORIGINS',
    default='http://localhost:3000,http://127.0.0.1:3000,https://agex.signox.great-site.net,http://102.207.222.11',
    cast=lambda v: [s.strip() for s in v.split(',')]
)

# Logging for production
LOGGING['handlers']['django_file']['filename'] = '/app/agex/logs/django.log'
LOGGING['handlers']['django_file']['formatter'] = 'json'
LOGGING['handlers']['celery_file']['filename'] = '/app/agex/logs/celery.log'
LOGGING['handlers']['celery_file']['formatter'] = 'json'
LOGGING['root']['level'] = config('LOG_LEVEL', default='WARNING')
LOGGING['loggers']['apps']['level'] = config('DJANGO_LOG_LEVEL', default='INFO')

# Email settings for production
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = True
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='benjaminkaranja8393@gmail.com')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='kdsijc amosa asoms')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@agex.com')

# Celery for production
CELERY_TASK_ALWAYS_EAGER = False
CELERY_TASK_EAGER_PROPAGATES = False
CELERY_BROKER_URL = config('CELERY_BROKER_URL', default='redis://redis-master:6379/0')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND', default='redis://redis-master:6379/1')

# Cache settings for production
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': config('REDIS_CACHE_URL', default='redis://redis-master:6379/2'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Session settings for production
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'

# Monitoring and metrics
PROMETHEUS_METRICS_ENABLED = config('PROMETHEUS_METRICS_ENABLED', default=True, cast=bool)

# Static files for production
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files for production
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
AWS_ACCESS_KEY_ID = config('AWS_ACCESS_KEY_ID', default=None)
AWS_SECRET_ACCESS_KEY = config('AWS_SECRET_ACCESS_KEY', default=None)
AWS_STORAGE_BUCKET_NAME = config('AWS_STORAGE_BUCKET_NAME', default=None)
AWS_S3_REGION_NAME = config('AWS_S3_REGION_NAME', default=None)
AWS_S3_CUSTOM_DOMAIN = config('AWS_S3_CUSTOM_DOMAIN', default=None)
AWS_DEFAULT_ACL = None
AWS_QUERYSTRING_AUTH = False
AWS_S3_OBJECT_PARAMETERS = {
    'CacheControl': 'max-age=86400',
}

# Google Cloud Configuration for Vertex AI
GOOGLE_CLOUD_PROJECT = config('GOOGLE_CLOUD_PROJECT', default='orbital-expanse-468309-m5')
GOOGLE_CLOUD_LOCATION = config('GOOGLE_CLOUD_LOCATION', default='us-central1')

# Vertex AI Configuration
VERTEX_AI_MODEL = config('VERTEX_AI_MODEL', default='gemini-2.0-flash-exp')
VERTEX_AI_QA_MODEL = config('VERTEX_AI_QA_MODEL', default='gemini-2.5-pro')
VERTEX_AI_EMBEDDING_MODEL = config('VERTEX_AI_EMBEDDING_MODEL', default='gemini-embedding-001')  # 768 dimensions
VERTEX_AI_TEMPERATURE = config('VERTEX_AI_TEMPERATURE', default=0.7, cast=float)
VERTEX_AI_TOP_P = config('VERTEX_AI_TOP_P', default=0.95, cast=float)
VERTEX_AI_TOP_K = config('VERTEX_AI_TOP_K', default=40, cast=int)
VERTEX_AI_MAX_OUTPUT_TOKENS = config('VERTEX_AI_MAX_OUTPUT_TOKENS', default=8192, cast=int)
VERTEX_AI_HARM_BLOCK_THRESHOLD = config('VERTEX_AI_HARM_BLOCK_THRESHOLD', default='BLOCK_MEDIUM_AND_ABOVE')
VERTEX_AI_MAX_REQUESTS_PER_MINUTE = config('VERTEX_AI_MAX_REQUESTS_PER_MINUTE', default=60, cast=int)
VERTEX_AI_MAX_TOKENS_PER_MINUTE = config('VERTEX_AI_MAX_TOKENS_PER_MINUTE', default=100000, cast=int)

# AI Service Configuration
USE_VERTEX_AI = config('USE_VERTEX_AI', default='true').lower() == 'true'

# Sentry for error tracking (optional)
SENTRY_DSN = config('SENTRY_DSN', default='')
if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    from sentry_sdk.integrations.celery import CeleryIntegration
    
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(auto_enabling=True),
            CeleryIntegration(auto_enabling=True),
        ],
        traces_sample_rate=0.1,
        send_default_pii=False,
        attach_stacktrace=True,
    )
