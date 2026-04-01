"""
SimpleJWT Configuration
========================

Defines ``SIMPLE_JWT``, the settings dictionary consumed by
``djangorestframework-simplejwt`` to control token issuance, validation,
and security.

Token lifecycle:
- **Access token** – short-lived (15 min) bearer token sent with every
  API request in the ``Authorization: Bearer <token>`` header.
- **Refresh token** – long-lived (7 days); sent to ``/api/token/refresh/``
  to obtain a new access token without re-authenticating.
- ``ROTATE_REFRESH_TOKENS = True``: a new refresh token is issued on
  every refresh call, limiting the window for refresh-token theft.
- ``BLACKLIST_AFTER_ROTATION = True``: the previous refresh token is
  immediately added to ``token_blacklist`` after rotation, preventing
  replay attacks.

Security:
- Algorithm: ``HS256`` (HMAC-SHA256) using the project ``SECRET_KEY``.
  Switch to ``RS256`` for multi-service architectures where resource
  servers need to verify tokens without access to ``SECRET_KEY``.
- ``UPDATE_LAST_LOGIN = False``: avoids a DB write on every token
  validation, which would create contention at scale.

Claims:
- ``USER_ID_FIELD / USER_ID_CLAIM``: maps the ``id`` field on the
  ``User`` model into the ``user_id`` JWT claim.
- ``JTI_CLAIM = "jti"``: unique token identifier; required for blacklist
  functionality.

Reference: https://django-rest-framework-simplejwt.readthedocs.io/
"""

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
