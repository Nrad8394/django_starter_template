"""
Authentication and Security Settings for the Application
==========================================================

This module contains all authentication-related configurations including:
- JWT settings
- CORS configuration
- CSRF settings
- Password validation
- Social authentication providers
- Security settings
- Session configuration
"""

from datetime import timedelta
from decouple import config
from .services import FRONTEND_URL, PLATFORM_NAME, SUPPORT_EMAIL

# CORS Settings
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost",
    "http://102.207.222.11",
]


CORS_ALLOW_CREDENTIALS = True

# CORS Headers for CSRF
CORS_ALLOW_HEADERS = [
    "accept",
    "accept-encoding",
    "authorization",
    "content-type",
    "dnt",
    "origin",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
    "X-Requested-With",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "cache-control",
    "pragma",
]

# Expose headers to the frontend
CORS_EXPOSE_HEADERS = [
    "content-type",
    "x-csrftoken",
]

# CORS Methods
CORS_ALLOW_METHODS = [
    "DELETE",
    "GET",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
]

# CSRF Settings
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

CSRF_COOKIE_NAME = "csrftoken"
CSRF_HEADER_NAME = "HTTP_X_CSRFTOKEN"
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript access to CSRF token
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_USE_SESSIONS = False

# Custom user model
# Custom user model
AUTH_USER_MODEL = "accounts.User"

# Authentication backends
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
]

# Allauth settings - Updated to use non-deprecated format
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
ACCOUNT_EMAIL_VERIFICATION = "optional"
ACCOUNT_LOGIN_METHODS = {"email"}
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_USER_MODEL_EMAIL_FIELD = "email"
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_AUTHENTICATION_METHOD = "email"
ACCOUNT_EMAIL_REQUIRED = True

# Email confirmation redirect URLs - redirect to frontend
ACCOUNT_EMAIL_CONFIRMATION_ANONYMOUS_REDIRECT_URL = f"{FRONTEND_URL}/auth/confirm-email"
ACCOUNT_EMAIL_CONFIRMATION_AUTHENTICATED_REDIRECT_URL = f"{FRONTEND_URL}/dashboard"
ACCOUNT_EMAIL_CONFIRMATION_URL = f"{FRONTEND_URL}/auth/confirm-email"

# Enhanced Social Authentication Configuration
SOCIALACCOUNT_PROVIDERS = {
    "google": {
        "APP": {"client_id": "", "secret": "", "key": ""},
        "SCOPE": [
            "profile",
            "email",
        ],
        "AUTH_PARAMS": {
            "access_type": "online",
        },
    },
    "github": {
        "APP": {
            "client_id": "",
            "secret": "",
        },
        "SCOPE": [
            "user:email",
        ],
    },
    "facebook": {
        "APP": {
            "client_id": "",
            "secret": "",
        },
        "METHOD": "oauth2",
        "SCOPE": ["email", "public_profile"],
        "AUTH_PARAMS": {"auth_type": "reauthenticate"},
        "INIT_PARAMS": {"cookie": True},
        "FIELDS": [
            "id",
            "email",
            "name",
            "first_name",
            "last_name",
            "verified",
            "locale",
            "timezone",
            "link",
            "gender",
            "updated_time",
        ],
        "EXCHANGE_TOKEN": True,
        "VERIFIED_EMAIL": False,
        "VERSION": "v13.0",
    },
}

# Enhanced Social Authentication Settings - API Only Configuration
SOCIALACCOUNT_QUERY_EMAIL = True
SOCIALACCOUNT_EMAIL_REQUIRED = True
SOCIALACCOUNT_EMAIL_VERIFICATION = "optional"
SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_LOGIN_ON_GET = False
SOCIALACCOUNT_STORE_TOKENS = True
# SOCIALACCOUNT_ADAPTER = 'apps.accounts.adapters.CustomSocialAccountAdapter'
# ACCOUNT_ADAPTER = 'apps.accounts.adapters.CustomAccountAdapter'

# Force API-only social authentication (no template rendering)
SOCIALACCOUNT_EMAIL_AUTHENTICATION = False
SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = False

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {
            "min_length": 8,
        },
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# Session Configuration
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_SAVE_EVERY_REQUEST = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = (
    False  # Changed to False to prevent logout on page navigation
)

# Security Settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

# Performance Settings
DB_QUERY_TIMEOUT = 30
API_TIMEOUT = 30
# FILE_UPLOAD_MAX_MEMORY_SIZE is configured in performance.py

# dj-rest-auth Configuration
REST_AUTH = {
    # Serializers
    "LOGIN_SERIALIZER": "apps.core.serializers.CustomLoginSerializer",
    "LOGOUT_SERIALIZER": "apps.core.serializers.CustomLogoutSerializer",
    "USER_DETAILS_SERIALIZER": "apps.accounts.serializers.UserDetailsSerializer",
    "REGISTER_SERIALIZER": "apps.core.serializers.CustomRegisterSerializer",
    "REGISTER_PERMISSION_CLASSES": ("rest_framework.permissions.DjangoModelPermissions",),

    # Password
    "PASSWORD_RESET_SERIALIZER": "dj_rest_auth.serializers.PasswordResetSerializer",
    "PASSWORD_RESET_CONFIRM_SERIALIZER": "dj_rest_auth.serializers.PasswordResetConfirmSerializer",
    "PASSWORD_CHANGE_SERIALIZER": "dj_rest_auth.serializers.PasswordChangeSerializer",
    "OLD_PASSWORD_FIELD_ENABLED": False,
    "LOGOUT_ON_PASSWORD_CHANGE": True,

    # Tokens
    "USE_JWT": True,
    "SESSION_LOGIN": False,  # Disable session authentication for APIs
    "JWT_AUTH_COOKIE": None,  # No cookies
    "JWT_AUTH_REFRESH_COOKIE": None,
    "JWT_AUTH_COOKIE_USE_CSRF": False,  # CSRF not needed
    "JWT_AUTH_HTTPONLY": False,
}

from datetime import timedelta

SIMPLE_JWT = {
    # Tokens
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),  # short-lived
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,  # rotate refresh tokens
    "BLACKLIST_AFTER_ROTATION": True,  # blacklist old refresh tokens

    # Headers
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",

    # Claims
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "TOKEN_TYPE_CLAIM": "token_type",
    "JTI_CLAIM": "jti",

    # Optional security
    "UPDATE_LAST_LOGIN": False,
    "ALGORITHM": "HS256",
}


# Allauth Configuration
ACCOUNT_AUTHENTICATION_METHOD = "email"
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_EMAIL_CONFIRMATION_EXPIRE_DAYS = 7
ACCOUNT_EMAIL_CONFIRMATION_ANONYMOUS_REDIRECT_URL = (
    f"{FRONTEND_URL}/auth/confirm-email?status=success"
)
ACCOUNT_EMAIL_CONFIRMATION_AUTHENTICATED_REDIRECT_URL = (
    f"{FRONTEND_URL}/auth/confirm-email?status=success"
)
ACCOUNT_RATE_LIMITS = {
    "login_failed": "5/300s",
    "login_success": "20/300s",
    "email_verification": "3/5m",
}
ACCOUNT_LOGOUT_REDIRECT_URL = f"{FRONTEND_URL}/auth/login"
ACCOUNT_SIGNUP_REDIRECT_URL = f"{FRONTEND_URL}/auth/login"
ACCOUNT_EMAIL_CONFIRMATION_HMAC = True
