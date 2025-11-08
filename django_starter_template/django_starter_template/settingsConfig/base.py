"""
Base Settings Configuration for the Application
===============================================

This module serves as the main settings file that imports configurations
from specialized modules for better maintainability and organization.
"""

import os
from pathlib import Path
from decouple import config

# -------------------------------------------------------------------
# 1. Environment and Path Configuration
# -------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY', default='django-insecure-dev-key-only-for-development-change-in-production-this-is-a-very-long-secret-key-with-many-characters')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=True, cast=bool)

ALLOWED_HOSTS = config('DJANGO_ALLOWED_HOSTS', default='localhost,127.0.0.1,136.115.191.246,agex.signox.co.ke', cast=lambda v: [s.strip() for s in v.split(',')])

# -------------------------------------------------------------------
# 2. Import Modular Configurations
# -------------------------------------------------------------------
# Import core Django settings (apps, middleware, database, etc.)
from .core import *

# Import authentication and security settings
from .auth import *

# Import API configuration (REST Framework, Spectacular)
from .api import *

# Import external services configuration ( email, etc.)
from .services import *

# Import storage configuration ( minio, AWS S3, redis etc.)
from .storage import *

# Import admin interface configuration
from .admin import *

# Import logging configuration
from .logging import *

# Import performance and caching configuration
from .performance import *

# -------------------------------------------------------------------
# 3. Import Celery Configuration
# -------------------------------------------------------------------
from .celery_config import *

# -------------------------------------------------------------------
# 4. Environment-Specific Overrides
# -------------------------------------------------------------------
# Import environment-specific settings (development, production, test)
# These can override any settings defined above
try:
    from .local import *
except ImportError:
    pass
