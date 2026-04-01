"""
Installed Applications Registry
================================

Defines the three application groups that together form
``INSTALLED_APPS``. Splitting them makes it easy to audit, reorder, or
conditionally include apps in environment-specific settings.

Groups:

``DJANGO_APPS``
    Core Django framework applications. ``jazzmin`` must appear first
    because it overrides Django admin templates; placing it after
    ``django.contrib.admin`` would break the custom admin UI.

``THIRD_PARTY_APPS``
    External packages installed from PyPI:
    - ``rest_framework`` + ``rest_framework_simplejwt``: JWT-based API.
    - ``corsheaders``: CORS support for frontend clients.
    - ``drf_spectacular``: OpenAPI 3 schema generation.
    - ``allauth`` + socialaccount providers: OAuth2 login (Google,
      GitHub, Facebook).
    - ``auth_kit`` (+ ``social``, ``mfa``): enhanced auth flows and
      multi-factor authentication support.
    - ``django_celery_beat`` / ``django_celery_results``: DB-backed
      Celery scheduler and task result storage.
    - ``storages``: pluggable file storage (S3/MinIO/GCS/Azure).

``LOCAL_APPS``
    First-party application modules within this repo:
    - ``apps.core``      – shared utilities, base models, pagination.
    - ``apps.accounts``  – custom User model, profiles, roles.
    - ``apps.security``  – rate limiting, audit logging, IP controls.
    - ``apps.notifications`` – in-app and email notification system.

``NSTALLED_APPS`` (sic) is the combined list; it is imported by
``base.py`` as the Django ``INSTALLED_APPS`` setting.
"""

# Application definition - This is constant across all environments
DJANGO_APPS = [
    "jazzmin",  # Must be before django.contrib.admin
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
]

THIRD_PARTY_APPS = [
    "rest_framework",
    "rest_framework.authtoken",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    "django_filters",
    "drf_spectacular",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.google",
    "allauth.socialaccount.providers.github",
    "allauth.socialaccount.providers.facebook",
    "auth_kit",
    "auth_kit.social",  # For social authentication
    "auth_kit.mfa",  # For MFA support
    "django_extensions",
    "django_redis",
    "django_celery_beat",  # Database-backed Celery scheduler
    "django_celery_results",
    "storages",  # Django-storages for MinIO/S3 support
]

LOCAL_APPS = [
    "apps.core.apps.CoreConfig",
    "apps.authentication.apps.AuthenticationConfig",
    # "apps.accounts.apps.AccountsConfig",
    # "apps.security.apps.SecurityConfig",
    # "apps.notifications.apps.NotificationsConfig",
]

INSTALLED_APPS = (
    DJANGO_APPS
    + THIRD_PARTY_APPS
    + LOCAL_APPS

)