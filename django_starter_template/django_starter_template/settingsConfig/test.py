"""
Test settings for agex project.
"""
from .base import *

# Use SQLite for tests to avoid PostgreSQL setup issues
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',  # Use in-memory database for faster tests
    }
}

# Use fast password hasher for tests
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Disable debug for tests
DEBUG = False

# Mock external service URL for tests
EXTERNAL_QUESTION_SERVICE_URL = 'http://mock-service.test/questions'

# Mock external service API key
EXTERNAL_SERVICE_API_KEY = 'mock-api-key'

# Use console email backend for tests
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Use local memory cache for tests
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}

# Test-specific settings
ALLOWED_HOSTS = ['testserver', 'localhost', '127.0.0.1']

# Configure logging to only use console handler in tests
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose'
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    }
}

# Explicitly remove debug toolbar from middleware in tests
MIDDLEWARE = [m for m in MIDDLEWARE if 'debug_toolbar' not in m]

# Remove debug toolbar from installed apps in tests
INSTALLED_APPS = [app for app in INSTALLED_APPS if app not in ['debug_toolbar', 'django_browser_reload']]

# Standard Django test runner (no pgvector needed for SQLite)
# TEST_RUNNER = 'ai_services.rag_engine.test_runner.PgVectorTestRunner'

# Disable system checks for tests to avoid model validation issues
SILENCED_SYSTEM_CHECKS = [
    'fields.E300',  # Field defines a relation with model that is not installed
]

# Celery settings for tests
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = False  # Don't propagate exceptions to caller

# Configure throttling for tests (can be overridden in individual tests)
REST_FRAMEWORK['DEFAULT_THROTTLE_RATES'] = {
    'anon': '100/hour',
    'user': '1000/hour',
    'content_generation': '60/minute',
    'assessment_generation': '20/minute',
    'agent_request': '100/minute',
    'burst': '10/minute',
}

# Content generation throttle rates for tests
CONTENT_GENERATION_THROTTLE_RATES = {
    'content_generation': '60/minute',
    'assessment_generation': '20/minute',
    'agent_request': '100/minute',
    'burst': '10/minute',
}