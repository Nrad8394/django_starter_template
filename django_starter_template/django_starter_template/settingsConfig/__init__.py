"""
Settings Configuration Module
==================================

This module provides a comprehensive, modular settings configuration for the Django application.
Settings are organized into logical modules for better maintainability and clarity.

Modules:
- base.py: Main settings file that imports from all modules
- core.py: Core Django settings (apps, middleware, database, etc.)
- auth.py: Authentication, JWT, CORS, and security settings
- api.py: REST Framework and API documentation settings
- services.py: External service configurations
- admin.py: Django admin interface configuration
- logging.py: Logging configuration
- performance.py: Caching and performance settings
- celery_config.py: Celery task queue configuration

Environment-specific settings can be added in:
- development.py: Development environment overrides
- production.py: Production environment overrides
- test.py: Test environment overrides
- local.py: Local machine-specific overrides (not in version control)
"""

__version__ = "1.0.0"
__author__ = "Development Team"