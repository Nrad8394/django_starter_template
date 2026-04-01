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
