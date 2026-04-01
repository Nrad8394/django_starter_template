"""
DRF Spectacular – OpenAPI 3 Schema Configuration
=================================================

Defines the ``SPECTACULAR_SETTINGS`` dictionary that controls how
``drf_spectacular`` generates and serves the OpenAPI 3 schema for this
project.

Includes:
- **Title / version / description**: pulled from ``SITE_NAME`` and
  environment variables so the docs stay accurate across deployments.
- **Authentication definitions**: ``JWTAuth`` (Bearer) and
  ``SessionAuth`` (cookie) security schemes wired into every operation.
- **Contact & license**: sourced from env vars
  (``CONTACT_NAME``, ``CONTACT_EMAIL``, ``LICENSE_NAME``) so they can
  differ between staging and production without code changes.
- **Swagger UI / ReDoc**: pre-configured with sensible UX defaults
  (deep linking, persistent auth, expanded models, try-it-out enabled).
- **Tag grouping**: all API tags are declared here; endpoint groups
  (Authentication, Users, Roles, Notifications, Security, …) each have
  a human-readable description shown in the Swagger UI sidebar.
- **Operation ID mapping**: explicit overrides for any endpoints that
  would otherwise produce colliding ``operationId`` values.

Access the live docs:
  - Swagger UI  → ``/api/v1/docs/``
  - ReDoc       → ``/api/v1/redoc/``
  - Raw schema  → ``/api/v1/schema/``

Reference: https://drf-spectacular.readthedocs.io/
"""

from ..env import get_env
from ..base import SITE_NAME

# DRF Spectacular Settings
SPECTACULAR_SETTINGS = {
    "TITLE": SITE_NAME + " API",
    "DESCRIPTION": "AI-powered tool that helps institutions automatically generate, review, and manage Assessments while ensuring alignment with curriculum materials.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "SCHEMA_PATH_PREFIX": "/api/",
    "COMPONENT_SPLIT_REQUEST": True,
    "SORT_OPERATIONS": False,
    # Authentication Configuration for Swagger
    "SECURITY": [{"JWTAuth": []}, {"SessionAuth": []}],
    "SECURITY_DEFINITIONS": {
        "JWTAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Enter JWT token in format: Bearer <token>",
        },
        "SessionAuth": {"type": "apiKey", "in": "cookie", "name": "sessionid"},
    },
    # API Contact and License Info
    "CONTACT": {
        "name": get_env("CONTACT_NAME", default=SITE_NAME + " Team"),
        "email": get_env("CONTACT_EMAIL", default="admin@" + SITE_NAME.lower() + ".com"),
    },
    "LICENSE": {
        "name": get_env("LICENSE_NAME", default="MIT License"),
    },
    # Swagger UI Configuration
    "SWAGGER_UI_SETTINGS": {
        "deepLinking": True,
        "persistAuthorization": True,
        "displayOperationId": False,
        "defaultModelsExpandDepth": 2,
        "defaultModelExpandDepth": 2,
        "displayRequestDuration": True,
        "docExpansion": "none",
        "filter": True,
        "showExtensions": True,
        "showCommonExtensions": True,
        "tryItOutEnabled": True,
    },
    # ReDoc Configuration
    "REDOC_UI_SETTINGS": {
        "nativeScrollbars": True,
        "theme": {
            "typography": {
                "fontSize": "14px",
                "lineHeight": "1.5em",
                "code": {
                    "fontSize": "13px",
                },
            },
            "menu": {
                "backgroundColor": "#fafafa",
            },
        },
    },
    # Schema Generation
    "PREPROCESSING_HOOKS": [],
    "POSTPROCESSING_HOOKS": [],
    "ENUM_NAME_OVERRIDES": {},
    "ENUM_GENERATE_CHOICE_DESCRIPTION": True,
    # Custom operation ID mapping to resolve collisions
    "OPERATION_ID_MAPPING": {
        # Accounts
        "accounts:user_permissions_list": "accounts_user_permissions_list",
        "accounts:user_permissions_retrieve": "accounts_user_permissions_retrieve",
    },
    # Tags for grouping endpoints
    "TAGS": [
        # Authentication & User Management
        {
            "name": "Authentication",
            "description": "User authentication and registration endpoints including social auth",
        },
        {"name": "Users", "description": "User management and profile operations"},
        {
            "name": "User Profiles",
            "description": "User profile management and extended user information",
        },
        {
            "name": "User Role History",
            "description": "User role change history and audit trail",
        },
        {
            "name": "User Sessions",
            "description": "User session management and activity tracking",
        },
        {
            "name": "Roles",
            "description": "Role management and permissions configuration",
        },
        {
            "name": "Login Attempts",
            "description": "Tracking and management of user login attempts",
        },
        {
            "name": "Permissions",
            "description": "Permission management and access control",
        },
        {
            "name": "Two-Factor Authentication",
            "description": "Endpoints for managing two-factor authentication setup and verification",
        },
        # Core System
        {
            "name": "Core",
            "description": "Core application functionality and health checks",
        },
        {
            "name": "Statistics",
            "description": "Statistical data and analytics endpoints",
        },
        # security and notifications
        {
            "name": "Security",
            "description": "Security features including rate limiting and audit logging",
        },
        {
            "name": "Notifications",
            "description": "User notifications and messaging system",
        },

    ],
}
