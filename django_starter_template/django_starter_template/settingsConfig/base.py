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

from .env import get_env

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# =============================================================================
# SECURITY: These should be overridden in production via environment variables
# =============================================================================
SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "django-insecure-dev-only-change-in-production",
)

DEBUG = get_env(
    "DEBUG",
    default=True,
    cast=lambda v: str(v).lower() in ("true", "1", "yes", "on"),
)

ALLOWED_HOSTS = get_env(
    "DJANGO_ALLOWED_HOSTS",
    default="localhost,127.0.0.1",
    cast=lambda v: [s.strip() for s in v.split(",")],
)

# =============================================================================
# Site config - Used across the project for branding (admin, API docs, etc.)
# =============================================================================
from .core.app_configs import *

# =============================================================================
# 1. Import admin Settings for admin interface 
# =============================================================================
from .admin.jazzmin import *
from .core.django_configs import *

# =============================================================================
# 2. Import API Settings for REST framework and API configuration
# =============================================================================
from .api.rest import *
from .api.spectacular import *

# =============================================================================
# 3. Import Auth Settings for authentication and authorization configuration
# =============================================================================
from .auth.rest import *
from .auth.auth_kit import *
from .auth.cors import *
from .auth.jwt import *

# =============================================================================
# 4. Import Core Settings for core Django configuration (middleware, templates, etc.)
# =============================================================================
from .core.apps import *
from .core.i18n_settings import *
from .core.middleware import *
from .core.django_configs import *

# =============================================================================
# 5. Import logging configuration
# =============================================================================
from .logging.logging import *

# =============================================================================
# 6. Import external services configuration (email, Celery, etc.)
# =============================================================================
from .services.email import *
from .services.celery import *
from .services.redis import *

# =============================================================================
# 7. Import perfomance and caching settings
# =============================================================================
from .perfomance.performance import *

# =============================================================================
# 8. Import storage settings (e.g., for MinIO/S3)
# =============================================================================
from .storage.storage_settings import *



