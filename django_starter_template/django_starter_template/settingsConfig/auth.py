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

# JWT Configuration
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': config('SECRET_KEY', default='django-insecure-dev-key-only-for-development-change-in-production-this-is-a-very-long-secret-key-with-many-characters'),
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'AUTH_HEADER_TYPES': ('Bearer',),
}

# CORS Settings
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

CORS_ALLOW_CREDENTIALS = True

# CORS Headers for CSRF
CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
    'X-Requested-With',
    'x-forwarded-for',
    'x-forwarded-proto',
    'x-forwarded-host',
    'cache-control',
    'pragma',
]

# Expose headers to the frontend
CORS_EXPOSE_HEADERS = [
    'content-type',
    'x-csrftoken',
]

# CORS Methods
CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

# CSRF Settings
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

CSRF_COOKIE_NAME = 'csrftoken'
CSRF_HEADER_NAME = 'HTTP_X_CSRFTOKEN'
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript access to CSRF token
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_USE_SESSIONS = False

# Custom user model
AUTH_USER_MODEL = 'accounts.User'

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

# Allauth settings - Updated to use non-deprecated format
ACCOUNT_SIGNUP_FIELDS = ['email*', 'password1*', 'password2*']
ACCOUNT_EMAIL_VERIFICATION = 'optional'
ACCOUNT_LOGIN_METHODS = {'email'}
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_USER_MODEL_EMAIL_FIELD = 'email'
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_AUTHENTICATION_METHOD = 'email'
ACCOUNT_EMAIL_REQUIRED = True

# Enhanced Social Authentication Configuration
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'APP': {
            'client_id': '',
            'secret': '',
            'key': ''
        },
        'SCOPE': [
            'profile',
            'email',
        ],
        'AUTH_PARAMS': {
            'access_type': 'online',
        }
    },
    'github': {
        'APP': {
            'client_id': '',
            'secret': '',
        },
        'SCOPE': [
            'user:email',
        ],
    },
    'facebook': {
        'APP': {
            'client_id': '',
            'secret': '',
        },
        'METHOD': 'oauth2',
        'SCOPE': ['email', 'public_profile'],
        'AUTH_PARAMS': {'auth_type': 'reauthenticate'},
        'INIT_PARAMS': {'cookie': True},
        'FIELDS': [
            'id',
            'email',
            'name',
            'first_name',
            'last_name',
            'verified',
            'locale',
            'timezone',
            'link',
            'gender',
            'updated_time',
        ],
        'EXCHANGE_TOKEN': True,
        'VERIFIED_EMAIL': False,
        'VERSION': 'v13.0',
    }
}

# Enhanced Social Authentication Settings - API Only Configuration
SOCIALACCOUNT_QUERY_EMAIL = True
SOCIALACCOUNT_EMAIL_REQUIRED = True
SOCIALACCOUNT_EMAIL_VERIFICATION = 'optional'
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
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Session Configuration
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_SAVE_EVERY_REQUEST = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Security Settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Performance Settings
DB_QUERY_TIMEOUT = 30
API_TIMEOUT = 30
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB

# dj-rest-auth Configuration
REST_AUTH = {
    'USE_JWT': True,
    'JWT_AUTH_COOKIE': 'access_token',
    'JWT_AUTH_REFRESH_COOKIE': 'refresh_token',
    'JWT_AUTH_SECURE': False,  # Set to True in production with HTTPS
    'JWT_AUTH_HTTPONLY': False,  # Allow JavaScript access for Postman cookie extraction
    'JWT_AUTH_SAMESITE': 'Lax',
    'JWT_AUTH_COOKIE_USE_CSRF': False,  # Disable CSRF for JWT cookies
    'USER_DETAILS_SERIALIZER': 'apps.accounts.serializers.UserDetailsSerializer',
    'REGISTER_SERIALIZER': 'apps.accounts.serializers.CustomRegisterSerializer',
    'LOGIN_SERIALIZER': 'apps.accounts.serializers.CustomLoginSerializer',
    'PASSWORD_CHANGE_SERIALIZER': 'apps.accounts.serializers.CustomPasswordChangeSerializer',
    'PASSWORD_RESET_SERIALIZER': 'apps.core.serializers.PasswordResetSerializer',  # Use custom serializer
    'JWT_SERIALIZER': 'apps.accounts.serializers.CustomJWTSerializer',
    'SOCIAL_LOGIN_SERIALIZER': 'apps.accounts.social_serializers.CustomSocialLoginSerializer',
    'SESSION_LOGIN': False,
    'LOGIN_URL': None,  # API-only, no redirect URLs
    'LOGOUT_URL': None,
    'PASSWORD_RESET_USE_SITES_DOMAIN': False,  # Don't use sites framework
    'SIGNUP_FIELDS': {
        'email': {'required': True},
        'username': {'required': False},
    },
    'OLD_PASSWORD_FIELD_ENABLED': True,
    'LOGOUT_ON_PASSWORD_CHANGE': False,
}