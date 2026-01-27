"""
Test Settings
=============

This module overrides base settings for running tests.

Key features:
- In-memory SQLite database (fast, no external DB needed)
- Fast password hasher (MD5, not for production!)
- Console email backend (no real emails)
- Local memory cache (no Redis needed)
- Minimal logging (only console)
- Celery in eager mode (tasks execute synchronously)
"""

from .base import *

# =============================================================================
# DATABASE
# =============================================================================
# Use in-memory SQLite for fast test execution
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

# =============================================================================
# SECURITY
# =============================================================================
# Fast password hasher for tests (DO NOT use in production!)
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

DEBUG = False

# =============================================================================
# EMAIL
# =============================================================================
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# =============================================================================
# CACHING
# =============================================================================
# Use local memory cache for tests (no Redis needed)
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

# =============================================================================
# HOSTS
# =============================================================================
ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]

# =============================================================================
# LOGGING
# =============================================================================
# Minimal logging for tests (only console)
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {process:d} {thread:d} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "verbose"},
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
}

# =============================================================================
# MIDDLEWARE AND APPS
# =============================================================================
# Remove debug tools from tests
MIDDLEWARE = [m for m in MIDDLEWARE if "debug_toolbar" not in m]
INSTALLED_APPS = [
    app for app in INSTALLED_APPS
    if app not in ["debug_toolbar", "django_browser_reload"]
]

# =============================================================================
# SYSTEM CHECKS
# =============================================================================
# Silence model-related system checks in tests
SILENCED_SYSTEM_CHECKS = [
    "fields.E300",  # Field defines relation with model that is not installed
]

# =============================================================================
# CELERY
# =============================================================================
# Execute Celery tasks synchronously (no worker needed for tests)
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = False

