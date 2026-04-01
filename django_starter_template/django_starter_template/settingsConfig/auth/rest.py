"""
dj-rest-auth Behavioral Configuration
======================================

Defines the ``REST_AUTH`` dictionary used by ``dj-rest-auth`` to wire
login, logout, registration, password management, and user detail
endpoints to the project's custom serializers.

Serialization:
- ``LOGIN_SERIALIZER`` / ``LOGOUT_SERIALIZER``: custom serializers in
  ``apps.core.serializers`` that extend dj-rest-auth defaults with
  project-specific validation and response shaping.
- ``USER_DETAILS_SERIALIZER``: ``apps.accounts.serializers.UserDetailsSerializer``
  – controls what user data is returned by ``/auth/user/``.
- ``REGISTER_SERIALIZER``: custom registration serializer that can
  enforce extra fields (e.g. first/last name) at sign-up.
- ``REGISTER_PERMISSION_CLASSES``: uses ``DjangoModelPermissions`` so
  only users with the ``accounts.add_user`` permission can register
  (useful for invite-only setups; override with ``AllowAny`` for open
  registration).

Password management:
- ``OLD_PASSWORD_FIELD_ENABLED = False``: users do not need to supply
  their current password to change it (assume they are already
  authenticated and the endpoint is JWT-protected).
- ``LOGOUT_ON_PASSWORD_CHANGE = True``: invalidates the current session
  and forces re-login after a password change for security.

Token strategy:
- ``USE_JWT = True``: dj-rest-auth returns JWT access/refresh pairs
  instead of DRF authtoken keys.
- ``SESSION_LOGIN = False``: session-based login is disabled for the
  API surface; cookie names are ``None`` so tokens are only transmitted
  in the ``Authorization`` header.
- ``JWT_AUTH_HTTPONLY = False``: allows the frontend to read the token
  from the response body (not a cookie) and store it in memory.

Reference: https://dj-rest-auth.readthedocs.io/
"""

REST_AUTH = {
    # # Serializers
    # "LOGIN_SERIALIZER": "apps.core.serializers.CustomLoginSerializer",
    # "LOGOUT_SERIALIZER": "apps.core.serializers.CustomLogoutSerializer",
    # "USER_DETAILS_SERIALIZER": "apps.accounts.serializers.UserDetailsSerializer",
    # "REGISTER_SERIALIZER": "apps.core.serializers.CustomRegisterSerializer",
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
