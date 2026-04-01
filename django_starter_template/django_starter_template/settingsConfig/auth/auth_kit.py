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
