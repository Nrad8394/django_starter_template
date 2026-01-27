"""
Base Settings Configuration
============================

This module serves as the foundation settings that imports core Django configuration
and all feature modules (auth, api, services, storage, etc.). It provides sensible
defaults that work for development.

This is NOT meant to be used directly. Environment-specific modules (development.py,
production.py, test.py) import from this and override settings as needed.

Settings hierarchy:
  base.py (imports core.py + feature modules with dev defaults)
    ↓
  development.py / production.py / test.py (overrides as needed)
"""

import os
from pathlib import Path
from decouple import config

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# =============================================================================
# SECURITY: These should be overridden in production via environment variables
# =============================================================================
SECRET_KEY = config(
    "SECRET_KEY",
    default="django-insecure-dev-only-change-in-production",
)

DEBUG = config("DEBUG", default=True, cast=bool)

ALLOWED_HOSTS = config(
    "DJANGO_ALLOWED_HOSTS",
    default="localhost,127.0.0.1",
    cast=lambda v: [s.strip() for s in v.split(",")],
)

# =============================================================================
# 1. Import Core App Configuration (CONSTANT across all environments)
# =============================================================================
from .core import *

# =============================================================================
# 2. Import Feature Modules with defaults
# =============================================================================
# Import services first since other modules depend on it (e.g., auth uses FRONTEND_URL)
from .services import *
from .auth import *
from .api import *
from .storage import *
from .admin import *
from .logging import *
from .performance import *

# =============================================================================
# 3. Import Celery Configuration
# =============================================================================
from .celery_config import *

# =============================================================================
# 4. DATABASE: Default to SQLite (overridden in production/Development)
# =============================================================================
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# =============================================================================
# 5. CACHING: Default to Redis with fallback to SQLite (overridden in test)
# =============================================================================
# Import REDIS_URL from storage config
from .storage import REDIS_URL

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

# =============================================================================
# Export all public settings for composition
# =============================================================================
__all__ = [name for name in globals() if not name.startswith("_")]

