"""
Logging Configuration for the Application
==========================================

This module contains comprehensive logging configurations including:
- Console and file logging handlers
- Log formatters (verbose and JSON)
- Logger configurations for different components
- Log rotation and retention settings
"""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Ensure logs directory exists to prevent FileNotFoundError when logging to files
LOGS_DIR = BASE_DIR / "logs"
try:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    # If we cannot create the logs directory (permissions, etc.),
    # fall back to console-only logging by leaving handlers to failover.
    pass

# Logging Configuration
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {process:d} {thread:d} {message}",
            "style": "{",
        },
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s",
        },
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "verbose"},
        "django_file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": str(LOGS_DIR / "django.log"),
            "formatter": "json",
            "when": "midnight",  # Rotate at midnight
            "backupCount": 30,  # Keep 30 days of logs
            "delay": True,
        },
        "celery_file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": str(LOGS_DIR / "celery.log"),
            "formatter": "verbose",
            "when": "midnight",  # Rotate at midnight
            "backupCount": 30,  # Keep 30 days of logs
            "delay": True,
        },
        "errors_file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": str(LOGS_DIR / "errors.log"),
            "level": "ERROR",
            "formatter": "verbose",
            "when": "midnight",
            "backupCount": 30,
            "delay": True,
        },
    },
    "root": {
        "handlers": ["console", "django_file", "celery_file", "errors_file"],
        "level": "INFO",
    },
    "loggers": {
        "django.request": {
            "handlers": ["console", "django_file"],
            "level": "ERROR",
            "propagate": False,
        },
        "apps": {
            "handlers": ["console", "django_file"],
            "level": "INFO",  # Reduced from DEBUG to INFO
            "propagate": False,
        },
        "celery": {
            "handlers": ["console", "celery_file"],
            "level": "INFO",
            "propagate": False,
        },
        "celery.beat": {
            "handlers": ["console", "celery_file"],
            "level": "INFO",
            "propagate": False,
        },
        "utils": {
            "handlers": ["console", "django_file"],
            "level": "ERROR",  # Suppress WARNING and INFO messages from utils logger
            "propagate": False,
        },
        # Suppress verbose boto3/botocore S3 debug logs
        "boto3": {
            "handlers": ["console", "django_file"],
            "level": "WARNING",
            "propagate": False,
        },
        "botocore": {
            "handlers": ["console", "django_file"],
            "level": "WARNING",
            "propagate": False,
        },
        "boto3.resources": {
            "handlers": ["console", "django_file"],
            "level": "WARNING",
            "propagate": False,
        },
        "botocore.auth": {
            "handlers": ["console", "django_file"],
            "level": "WARNING",
            "propagate": False,
        },
        "botocore.hooks": {
            "handlers": ["console", "django_file"],
            "level": "WARNING",
            "propagate": False,
        },
        "botocore.regions": {
            "handlers": ["console", "django_file"],
            "level": "WARNING",
            "propagate": False,
        },
        "urllib3": {
            "handlers": ["console", "django_file"],
            "level": "WARNING",
            "propagate": False,
        },
        # redis-py 8.x probes for `CLIENT MAINT_NOTIFICATIONS` on every new
        # connection; servers before Redis 8.2 reject it and the client
        # degrades gracefully, logging one DEBUG line per connection. Under a
        # DEBUG root (development) that buries the Celery output entirely.
        # INFO here keeps real connection errors, which log at WARNING+.
        "redis": {
            "handlers": ["console", "django_file"],
            "level": "INFO",
            "propagate": False,
        },
        "s3transfer": {
            "handlers": ["console", "django_file"],
            "level": "WARNING",
            "propagate": False,
        },
        "s3transfer.tasks": {
            "handlers": ["console", "django_file"],
            "level": "WARNING",
            "propagate": False,
        },
        "s3transfer.futures": {
            "handlers": ["console", "django_file"],
            "level": "WARNING",
            "propagate": False,
        },
        "s3transfer.utils": {
            "handlers": ["console", "django_file"],
            "level": "WARNING",
            "propagate": False,
        },
    },

}
