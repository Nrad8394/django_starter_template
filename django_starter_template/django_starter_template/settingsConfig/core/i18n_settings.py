"""
Internationalization and localization settings.

This file centralizes i18n get_envuration including language, timezone,
and locale settings.

Reference: https://docs.djangoproject.com/en/stable/topics/i18n/
"""
from ..env import get_env
# ============================================================================
# LANGUAGE & LOCALIZATION
# ============================================================================

# Language settings
LANGUAGE_CODE = get_env('LANGUAGE_CODE', default='en-us')

# List of languages available for selection
LANGUAGES = [
    ('en', 'English'),
    ('es', 'Spanish'),
    ('fr', 'French'),
    ('de', 'German'),
    ('sw', 'Swahili'),  # For East Africa
]

# Locale name to app-list form
USE_I18N = get_env('USE_I18N', default=True, cast=bool)

# Internationalized format strings (i.e., use local formatting of data)
USE_L10N = get_env('USE_L10N', default=True, cast=bool)

# ============================================================================
# TIMEZONE
# ============================================================================

# Timezone for the database
TIME_ZONE = get_env('TIME_ZONE', default='Africa/Nairobi')

# Use timezone-aware datetimes in the ORM
USE_TZ = get_env('USE_TZ', default=True, cast=bool)

# ============================================================================
# LOCALE PATHS
# ============================================================================

# Paths to look for localization files
import os
LOCALE_PATHS = [
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), 'locale'),
]

# ============================================================================
# DATE/TIME FORMAT
# ============================================================================

# Custom date/time formats for display (used if USE_L10N is False)
DATE_FORMAT = get_env('DATE_FORMAT', default='Y-m-d')
TIME_FORMAT = get_env('TIME_FORMAT', default='H:i:s')
DATETIME_FORMAT = get_env('DATETIME_FORMAT', default='Y-m-d H:i:s')
SHORT_DATE_FORMAT = get_env('SHORT_DATE_FORMAT', default='m/d/Y')
SHORT_DATETIME_FORMAT = get_env('SHORT_DATETIME_FORMAT', default='m/d/Y P')
