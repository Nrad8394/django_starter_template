"""
Social Authentication Provider Configuration
=============================================

Configures ``SOCIALACCOUNT_PROVIDERS`` for ``django-allauth`` / ``auth-kit``
to enable OAuth2 sign-in with Google, GitHub, and Facebook.

Configuration notes:
- **Google**: requests ``profile`` and ``email`` scopes with
  ``access_type=online``. App credentials (``client_id``, ``secret``)
  must be injected at runtime via the Django Sites/Allauth admin or
  overridden in environment-specific settings.
- **GitHub**: requests ``user:email`` so the account's primary (verified)
  email address is always available after sign-in.
- **Facebook**: uses OAuth2 with ``email`` + ``public_profile`` scopes.
  ``VERIFIED_EMAIL=False`` is intentional — Facebook email addresses are
  not always confirmed; implement extra verification in your pipeline if
  needed. ``EXCHANGE_TOKEN=True`` exchanges the short-lived client token
  for a longer-lived server-side token.

IMPORTANT: Never commit real ``client_id`` or ``secret`` values here.
Store them in environment variables or the Allauth ``SocialApp`` table.

Reference: https://docs.allauth.org/en/latest/socialaccount/providers/
"""

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
