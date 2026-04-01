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
    "apps.accounts.apps.AccountsConfig",
    "apps.security.apps.SecurityConfig",
    "apps.notifications.apps.NotificationsConfig",
]

NSTALLED_APPS = (
    DJANGO_APPS
    + THIRD_PARTY_APPS
    + LOCAL_APPS

)