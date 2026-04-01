
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
