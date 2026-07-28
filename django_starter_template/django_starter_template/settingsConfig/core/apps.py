"""
Installed Applications Registry
================================

``INSTALLED_APPS`` split into three groups so it is obvious at a glance what
is Django's, what is a dependency, and what is yours.

Ordering constraints that are not obvious
-----------------------------------------

* ``jazzmin`` must precede ``django.contrib.admin``. It overrides admin
  templates, and Django's template loader takes the first match — put it
  after and the override never applies.
* ``django_otp`` must be present whenever ``OTPMiddleware`` is in
  ``MIDDLEWARE``. This is a real trap: the middleware imports fine on its own
  and only fails when it touches the ORM, so the mistake surfaces as a
  confusing runtime error on the first request rather than at startup.
  (The version of this file that this replaces had exactly that mismatch.)
* ``allauth.account.middleware.AccountMiddleware`` is likewise required by
  allauth ≥0.56; the two must be enabled or disabled together.

Every app listed here has a startup and per-request cost. Delete what you do
not use — a starter template is a menu, not a prescription. In particular
``jazzmin``, the social providers, ``django_celery_beat``, ``storages`` and
``django_extensions`` are each independently removable.
"""

DJANGO_APPS = [
    "jazzmin",  # must come before django.contrib.admin — see module docstring
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",  # required by allauth
]

THIRD_PARTY_APPS = [
    # --- API ---
    "rest_framework",
    "rest_framework.authtoken",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",  # required for logout/rotation
    "django_filters",
    "drf_spectacular",
    "corsheaders",
    # --- Authentication ---
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    # Social providers cost a small amount of startup time each. Enable only
    # the ones you actually offer.
    "allauth.socialaccount.providers.google",
    # "allauth.socialaccount.providers.github",
    # "allauth.socialaccount.providers.facebook",
    # --- Multi-factor auth ---
    # Required by `django_otp.middleware.OTPMiddleware`. Remove both together.
    "django_otp",
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_static",
    # --- Background work ---
    "django_celery_beat",  # database-backed periodic task schedule
    "django_celery_results",  # task results in the database
    # --- Utilities ---
    "django_extensions",  # shell_plus, graph_models, runserver_plus
    "storages",  # S3 / MinIO / GCS / Azure file storage
]

LOCAL_APPS = [
    "apps.core.apps.CoreConfig",
    # Provides AUTH_USER_MODEL ("accounts.User"). Must stay enabled.
    "apps.accounts.apps.AccountsConfig",
    # Shipped commented-out as "optional", but apps/core/services.py imports
    # apps.security.models.AuditLog at module scope — so core never actually
    # worked without it, and `manage.py check` failed on a fresh checkout with
    # an app_label error. Projects that genuinely do not want it should
    # remove the AuditLog import from apps/core/services.py in the same change.
    "apps.security.apps.SecurityConfig",
    # ------------------------------------------------------------------
    # apps.notifications — DISABLED, deliberately. Enabling it cost 12 test
    # failures and took the suite from seconds to 16m30s. Three defects, all
    # pre-existing in the template:
    #
    #   1. signals.py:41 calls send_notification.delay() inside a post_save
    #      handler and reaches the broker even under CELERY_TASK_ALWAYS_EAGER.
    #      With no Redis running, each save blocks on a TCP connect timeout —
    #      142 of them across the suite. A signal must never do network I/O.
    #   2. signals.py:251 imports `apps.workflow`, an app that does not exist.
    #   3. signals.py:203 assumes every User has `notification_preferences`;
    #      nothing creates it, so the handler raises on every user.
    #
    # If your project needs outbound messaging, rework it first: move the send
    # out of signals into an explicitly-called service. Re-enable only after
    # that rework — do not switch this on as-is.
    # "apps.notifications.apps.NotificationsConfig",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS
