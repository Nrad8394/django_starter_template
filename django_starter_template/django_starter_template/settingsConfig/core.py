"""
Core Django App Configuration
==============================

This module defines Django's core app list, middleware stack, and fundamental
app-level settings. These are consistent across all environments and should NOT
be overridden.

Environment-specific settings (DEBUG, ALLOWED_HOSTS, DATABASES, etc.) are
defined in base.py and overridden in environment modules (development.py, etc).
"""

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

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
    "dj_rest_auth",
    "dj_rest_auth.registration",
    "django_extensions",
    "django_redis",
    "django_celery_beat",  # Database-backed Celery scheduler
    "django_celery_results",
    "storages",  # Django-storages for MinIO/S3 support
    "django_otp",  # Two-factor authentication
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_hotp",
    "django_otp.plugins.otp_static",
]

LOCAL_APPS = [
    "apps.core.apps.CoreConfig",
    "apps.accounts.apps.AccountsConfig",
    "apps.security.apps.SecurityConfig",
    "apps.notifications.apps.NotificationsConfig",
]

INSTITUTION_APPS = [
    "institution.institution_core.apps.InstitutionCoreConfig",
    "institution.academics.apps.AcademicsConfig",
]

TIMEX_APPS = [
    "timex.timetabling.apps.TimetablingConfig",
    "timex.resources.apps.ResourcesConfig",
]

LOGX_APPS = [
    "logx.attendance.apps.AttendanceConfig",
]

INSTALLED_APPS = (
    DJANGO_APPS
    + THIRD_PARTY_APPS
    + LOCAL_APPS
    + INSTITUTION_APPS
    + TIMEX_APPS
    + LOGX_APPS
)

# Middleware stack - Consistent across all environments
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "apps.core.middleware.APICSRFMiddleware",  # Custom CSRF middleware for API
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_otp.middleware.OTPMiddleware",
    "apps.core.middleware.CurrentUserMiddleware",  # Set current user in thread locals for audit fields
    "apps.accounts.middleware.LoginSecurityMiddleware",  # Login security enforcement
    "apps.accounts.middleware.SessionActivityMiddleware",  # Track session activity
    "apps.security.middleware.RateLimitMiddleware",  # Rate limiting
    "apps.security.middleware.AuditLogMiddleware",  # Audit logging
    "allauth.account.middleware.AccountMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.core.middleware.RequestTracingMiddleware",
    "apps.core.middleware.PerformanceMiddleware",
    "apps.core.middleware.ErrorHandlingMiddleware",
]

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

# Internationalization - Consistent across environments
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Africa/Nairobi"
USE_I18N = True
USE_TZ = True

# Static and Media URLs - Consistent across environments
STATIC_URL = "/api/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

MEDIA_URL = "/api/media/"
# MEDIA_ROOT is configured via Django storages (MinIO/S3)

# Default primary key field type
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Site ID for django-allauth
SITE_ID = 1

# Data Upload limits - Consistent across environments
DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB
DATA_UPLOAD_MAX_NUMBER_FIELDS = 1000

# Custom user model - Constant
AUTH_USER_MODEL = "accounts.User"

