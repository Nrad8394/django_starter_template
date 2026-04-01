"""
Development Settings
====================

This module overrides base settings for local development environment.

Key features:
- DEBUG enabled for development
- SQLite database (no external DB needed)
- All hosts allowed (simplifies testing)
- Console email backend (no real email sent)
- Debug toolbar and browser reload enabled
- Lenient CORS and CSRF for local frontend
- Detailed logging
"""

from .base import *
from copy import deepcopy
import warnings
import sys
import fnmatch

# Suppress specific warnings in development
warnings.filterwarnings("ignore", module="dj_rest_auth.registration.serializers")
warnings.filterwarnings("ignore", message=".*USERNAME_REQUIRED is deprecated.*")
warnings.filterwarnings("ignore", message=".*EMAIL_REQUIRED is deprecated.*")
warnings.filterwarnings("ignore", message=".*AUTHENTICATION_METHOD is deprecated.*")
warnings.filterwarnings("ignore", message=".*operationId .* has collisions.*")

# =============================================================================
# DEBUG AND SECURITY
# =============================================================================
DEBUG = True
ALLOWED_HOSTS = ["*"]  # Allow all hosts in development

# Disable HTTPS in development
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
CSRF_COOKIE_DOMAIN = None
CSRF_COOKIE_PATH = "/"

# =============================================================================
# DATABASE
# =============================================================================
# Use SQLite for easy local development (no PostgreSQL setup needed)
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
        "OPTIONS": {
            "timeout": 60,
        },
    }
}

# DATABASES = {
#     "default": {
#         "ENGINE": "django.db.backends.postgresql",
#         "NAME": get_env("POSTGRES_DB", default="django_starter_template_db"),
#         "USER": get_env("POSTGRES_USER", default="postgres"),
#         "PASSWORD": get_env("POSTGRES_PASSWORD", default=""),
#         "HOST": get_env("DB_HOST", default="localhost"),
#         "PORT": get_env("DB_PORT", default="5433", cast=int),
#         "CONN_MAX_AGE": 0,  # Disable persistent connections with PgBouncer
#         "CONN_HEALTH_CHECKS": True,
#     }
# }

# =============================================================================
# CACHING
# =============================================================================
# Try to use Redis, but don't fail if it's not available
try:
    from .base import REDIS_URL
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": REDIS_URL,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
            },
        }
    }
except Exception:
    # Fallback to local memory cache if Redis is not available
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    }

# =============================================================================
# CORS
# =============================================================================
# Allow all origins for easier local development and testing
CORS_ALLOW_ALL_ORIGINS = True

# =============================================================================
# DEBUG TOOLBAR AND DEVELOPMENT TOOLS
# =============================================================================
NSTALLED_APPS += [
    "debug_toolbar",
    "django_browser_reload",
]
MIDDLEWARE += [
    "debug_toolbar.middleware.DebugToolbarMiddleware",
    "django_browser_reload.middleware.BrowserReloadMiddleware",
]

INTERNAL_IPS = ["127.0.0.1", "localhost"]

DEBUG_TOOLBAR_CONFIG = {
    "SHOW_TOOLBAR_CALLBACK": lambda request: DEBUG,
    "IS_RUNNING_TESTS": False,
    "RENDER_PANELS": True,
    "SHOW_TEMPLATE_CONTEXT": True,
    "ENABLE_STACKTRACES": True,
    "DISABLE_PANELS": [
        "debug_toolbar.panels.cache.CachePanel",
        "debug_toolbar.panels.staticfiles.StaticFilesPanel",
        "debug_toolbar.panels.profiling.ProfilingPanel",
        "debug_toolbar.panels.request.RequestPanel",
    ],
    "CONSOLE_LOG_LEVEL": "WARNING",
}

# =============================================================================
# CELERY
# =============================================================================
# Use actual Celery workers for async tasks (not eager mode)
CELERY_TASK_ALWAYS_EAGER = False
CELERY_TASK_EAGER_PROPAGATES = False

# =============================================================================
# LOGGING
# =============================================================================
# Make logging more verbose for development
LOGGING = deepcopy(LOGGING)
LOGGING["root"]["level"] = "DEBUG"
LOGGING["loggers"]["apps"]["level"] = "DEBUG"

# Silence noisy libraries
LOGGING["loggers"]["debug_toolbar"] = {
    "handlers": ["console"],
    "level": "WARNING",
    "propagate": False,
}
LOGGING["loggers"]["dj_rest_auth"] = {
    "handlers": ["console"],
    "level": "ERROR",
    "propagate": False,
}
LOGGING["loggers"]["django.server"] = {
    "handlers": ["console"],
    "level": "WARNING",
    "propagate": False,
}
LOGGING["loggers"]["django.core.cache"] = {
    "handlers": ["console"],
    "level": "WARNING",
    "propagate": False,
}

# =============================================================================
# API / SPECTACULAR
# =============================================================================
# Suppress operationId collision warnings in development
SPECTACULAR_SETTINGS = SPECTACULAR_SETTINGS.copy()
SPECTACULAR_SETTINGS["COMPONENT_SPLIT_REQUEST"] = True
SPECTACULAR_SETTINGS["POSTPROCESSING_HOOKS"] = []

# =============================================================================
# DJANGO AUTORELOAD
# =============================================================================
# Prevent autoreload from restarting Celery workers and losing task state
def skip_celery_files(file_path):
    """Skip Celery-related files from Django autoreload."""
    celery_patterns = [
        "**/celery.py",
        "**/tasks.py",
        "**/apps.py",
        "**/services/**",
        "**/management/commands/**",
    ]
    for pattern in celery_patterns:
        if fnmatch.fnmatch(file_path, pattern):
            return True
    return False


try:
    from django.utils import autoreload
    autoreload.skip_reloader_filter = skip_celery_files
except ImportError:
    pass

