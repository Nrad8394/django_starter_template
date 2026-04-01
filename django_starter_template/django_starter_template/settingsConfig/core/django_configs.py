"""
Core Django Framework Settings
================================

Contains fundamental Django configuration that is constant across all
deployment environments (development, staging, production, test). These
settings should rarely need to be changed; environment-specific behaviour
is controlled by the overlaying ``development.py`` / ``production.py``
modules.

Settings defined here:

- ``BASE_DIR``: absolute path to the project root (three levels up from
  this file). Used as the base for constructing paths to templates,
  static files, and the SQLite fallback database.
- ``ROOT_URLCONF``: entry-point URL configuration module.
- ``TEMPLATES``: Django template engine configuration. Uses
  ``APP_DIRS=True`` so each installed app's ``templates/`` folder is
  discovered automatically. Includes the standard context processors for
  authentication, messages, and debug mode.
- ``WSGI_APPLICATION``: WSGI callable for synchronous WSGI servers
  (gunicorn, uWSGI).
- ``DEFAULT_AUTO_FIELD``: sets ``BigAutoField`` as the default primary
  key type for all models, avoiding migrations when upgrading from Django
  versions that defaulted to ``AutoField``.
- ``SITE_ID = 1``: required by ``django.contrib.sites`` and
  ``django-allauth``.
- ``DATA_UPLOAD_MAX_MEMORY_SIZE`` / ``DATA_UPLOAD_MAX_NUMBER_FIELDS``:
  guards against large in-memory uploads and form-field flooding.
- ``AUTH_USER_MODEL``: points Django and DRF to the custom User model
  in ``apps.accounts``.

Reference: https://docs.djangoproject.com/en/stable/ref/settings/
"""

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Root URL configuration - Consistent across environments
ROOT_URLCONF = "django_starter_template.urls"

# Template configuration - Consistent across environments
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "django_starter_template.wsgi.application"

# Default primary key field type
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Site ID for django-allauth
SITE_ID = 1

# Data Upload limits - Consistent across environments
DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB
DATA_UPLOAD_MAX_NUMBER_FIELDS = 1000

# Custom user model - Constant
AUTH_USER_MODEL = "authentication.User"

