"""
File storage and CDN configuration.

This file centralizes settings for file uploads, storage backends (local/S3),
and CDN configuration for optimal media file handling.

Supports multiple backends: Local filesystem, AWS S3, Google Cloud Storage, etc.

Reference: https://django-storages.readthedocs.io/
"""
import os
from ..env import get_env

# Project root directory (mylandlord-backend/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# ============================================================================
# STORAGE BACKEND SELECTION
# ============================================================================

# Storage backend type: 'local', 's3', 'gcs', 'azure'
STORAGE_BACKEND_TYPE = get_env('STORAGE_BACKEND_TYPE', default='local')

# Map backend types to django-storages classes
STORAGE_BACKEND_MAP = {
    'local': 'django.core.files.storage.FileSystemStorage',
    's3': 'storages.backends.s3boto3.S3Boto3Storage',
    'gcs': 'storages.backends.gcloud.GoogleCloudStorage',
    'azure': 'storages.backends.azure_storage.AzureStorage',
}

# Default storage backend
DEFAULT_FILE_STORAGE = STORAGE_BACKEND_MAP.get(
    STORAGE_BACKEND_TYPE,
    STORAGE_BACKEND_MAP['local']
)

# ============================================================================
# LOCAL FILE STORAGE SETTINGS
# ============================================================================

# Local media files location
MEDIA_ROOT = get_env(
    'MEDIA_ROOT',
    default=os.path.join(PROJECT_ROOT, 'media')
)

# Create media directory if it doesn't exist
os.makedirs(MEDIA_ROOT, exist_ok=True)

# URL for accessing uploaded media files
MEDIA_URL = get_env('MEDIA_URL', default='/media/')

# Maximum file upload size (in bytes) - 100 MB default
DATA_UPLOAD_MAX_MEMORY_SIZE = get_env('DATA_UPLOAD_MAX_MEMORY_SIZE', default=104857600, cast=int)
FILE_UPLOAD_MAX_MEMORY_SIZE = get_env('FILE_UPLOAD_MAX_MEMORY_SIZE', default=104857600, cast=int)

# Allowed extensions for file uploads
ALLOWED_FILE_EXTENSIONS = {
    'images': ['jpg', 'jpeg', 'png', 'gif', 'webp'],
    'documents': ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt'],
    'videos': ['mp4', 'mov', 'avi', 'mkv'],
}

# ============================================================================
# AWS S3 STORAGE SETTINGS
# ============================================================================

# AWS S3 access credentials
AWS_ACCESS_KEY_ID = get_env('AWS_ACCESS_KEY_ID', default=None)
AWS_SECRET_ACCESS_KEY = get_env('AWS_SECRET_ACCESS_KEY', default=None)

# AWS S3 configuration
AWS_STORAGE_BUCKET_NAME = get_env('AWS_STORAGE_BUCKET_NAME', default=None)
AWS_S3_REGION_NAME = get_env('AWS_S3_REGION_NAME', default='us-east-1')
AWS_S3_ENDPOINT_URL = get_env('AWS_S3_ENDPOINT_URL', default=None)

# S3 file upload settings
AWS_S3_CUSTOM_DOMAIN = get_env('AWS_S3_CUSTOM_DOMAIN', default=None)
AWS_S3_USE_SSL = get_env('AWS_S3_USE_SSL', default=True, cast=lambda v: str(v).lower() in ("true", "1", "yes", "on"))
AWS_S3_VERIFY = get_env('AWS_S3_VERIFY', default=True, cast=lambda v: str(v).lower() in ("true", "1", "yes", "on"))

# S3 file access settings
AWS_S3_SIGNATURE_VERSION = get_env('AWS_S3_SIGNATURE_VERSION', default='s3v4')
AWS_S3_ADDRESSING_STYLE = get_env('AWS_S3_ADDRESSING_STYLE', default='virtual')

# S3 ACL and permissions
AWS_DEFAULT_ACL = get_env('AWS_DEFAULT_ACL', default='public-read')
AWS_S3_OBJECT_PARAMETERS = {
    'CacheControl': 'max-age=86400',
}

# ============================================================================
# GOOGLE CLOUD STORAGE SETTINGS
# ============================================================================

# Google Cloud Storage configuration
GCS_BUCKET_NAME = get_env('GCS_BUCKET_NAME', default=None)
GCS_PROJECT_ID = get_env('GCS_PROJECT_ID', default=None)
GCS_LOCATION = get_env('GCS_LOCATION', default='')

# Google Cloud credentials (can be JSON key file path or JSON string)
GOOGLE_APPLICATION_CREDENTIALS = get_env('GOOGLE_APPLICATION_CREDENTIALS', default=None)

# ============================================================================
# AZURE STORAGE SETTINGS
# ============================================================================

# Azure Storage configuration
AZURE_ACCOUNT_NAME = get_env('AZURE_ACCOUNT_NAME', default=None)
AZURE_ACCOUNT_KEY = get_env('AZURE_ACCOUNT_KEY', default=None)
AZURE_CONTAINER = get_env('AZURE_CONTAINER', default='media')
AZURE_CUSTOM_DOMAIN = get_env('AZURE_CUSTOM_DOMAIN', default=None)

# ============================================================================
# MINIO STORAGE SETTINGS
# ============================================================================

# MinIO is an S3-compatible object storage service (used for local self-hosted)
MINIO_ENDPOINT = get_env('MINIO_ENDPOINT', default='localhost:9000')
MINIO_ACCESS_KEY = get_env('MINIO_ACCESS_KEY', default='minioadmin')
MINIO_SECRET_KEY = get_env('MINIO_SECRET_KEY', default='minioadmin')
MINIO_BUCKET_NAME = get_env('MINIO_BUCKET_NAME', default='smartlandlord')
MINIO_USE_SSL = get_env('MINIO_USE_SSL', default=False, cast=lambda v: str(v).lower() in ("true", "1", "yes", "on"))
MINIO_SECURE = get_env('MINIO_SECURE', default=False, cast=lambda v: str(v).lower() in ("true", "1", "yes", "on"))

# MinIO URL for external access (e.g., from frontend)
MINIO_URL = get_env('MINIO_URL', default='http://localhost:9000')
MINIO_PUBLIC_URL = get_env('MINIO_PUBLIC_URL', default='http://localhost:9000')

# MinIO custom domain (optional, for CDN)
MINIO_CUSTOM_DOMAIN = get_env('MINIO_CUSTOM_DOMAIN', default=None)

# MinIO storage configuration for django-storages
if STORAGE_BACKEND_TYPE == 'minio':
    # Use minio backend (requires django-minio-backend)
    DEFAULT_FILE_STORAGE = 'minio_backend.storage.MinioMediaStorage'
    # Additional minio-specific settings can be added here

# ============================================================================
# CDN CONFIGURATION
# ============================================================================

# CDN URL for static and media files (optional, for faster content delivery)
CDN_URL = get_env('CDN_URL', default=None)
CDN_USE_SSL = get_env('CDN_USE_SSL', default=True, cast=lambda v: str(v).lower() in ("true", "1", "yes", "on"))

# Cloudflare CDN settings (if using Cloudflare)
CLOUDFLARE_ZONE_ID = get_env('CLOUDFLARE_ZONE_ID', default=None)
CLOUDFLARE_API_KEY = get_env('CLOUDFLARE_API_KEY', default=None)

# ============================================================================
# STATIC FILES SETTINGS
# ============================================================================

# Static files location
STATIC_ROOT = get_env(
    'STATIC_ROOT',
    default=os.path.join(PROJECT_ROOT, 'staticfiles')
)

# Static files URL
STATIC_URL = get_env('STATIC_URL', default='/static/')

# Additional static file directories
_extra_static_dir = get_env('STATICFILES_EXTRA_DIR', default=os.path.join(PROJECT_ROOT, 'mylandlord-files-static'))
STATICFILES_DIRS = [_extra_static_dir] if os.path.isdir(_extra_static_dir) else []

# Static files storage backend (for collectstatic)
STATICFILES_STORAGE = get_env(
    'STATICFILES_STORAGE',
    default='django.contrib.staticfiles.storage.StaticFilesStorage'
)

# ============================================================================
# FILE UPLOAD SETTINGS
# ============================================================================

# Temporary uploads directory
FILE_UPLOAD_TEMP_DIR = get_env('FILE_UPLOAD_TEMP_DIR', default=None)

# File upload permissions
FILE_UPLOAD_PERMISSIONS = get_env('FILE_UPLOAD_PERMISSIONS', default=0o644, cast=int)
FILE_UPLOAD_DIRECTORY_PERMISSIONS = get_env('FILE_UPLOAD_DIRECTORY_PERMISSIONS', default=0o755, cast=int)

# Handlers for file uploads
FILE_UPLOAD_HANDLERS = [
    'django.core.files.uploadhandler.MemoryFileUploadHandler',
    'django.core.files.uploadhandler.TemporaryFileUploadHandler',
]

# ============================================================================
# IMAGE PROCESSING SETTINGS
# ============================================================================

# Pillow/image processing settings
THUMBNAIL_BACKEND = get_env('THUMBNAIL_BACKEND', default='sorl.thumbnail.base.ThumbnailBackend')
THUMBNAIL_DEBUG = get_env('THUMBNAIL_DEBUG', default=False, cast=bool)
THUMBNAIL_SIZE = (300, 300)

# Image conversion settings
IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'webp']
OPTIMIZE_IMAGES = get_env('OPTIMIZE_IMAGES', default=True, cast=bool)

# ============================================================================
# PRIVATE VS PUBLIC FILES
# ============================================================================

# Private media storage (for authenticated users only)
PRIVATE_STORAGE_LOCATION = get_env('PRIVATE_STORAGE_LOCATION', default='private/')
PUBLIC_STORAGE_LOCATION = get_env('PUBLIC_STORAGE_LOCATION', default='public/')

# ============================================================================
# FILE CLEANUP & MAINTENANCE
# ============================================================================

# Delete files when models are deleted
DELETE_FILES_ON_MODEL_DELETE = get_env('DELETE_FILES_ON_MODEL_DELETE', default=True, cast=bool)

# Maximum age for temporary files (in seconds)
TEMP_FILE_MAX_AGE = get_env('TEMP_FILE_MAX_AGE', default=86400, cast=int)  # 24 hours

# ============================================================================
# DJANGO STORAGES CONFIGURATION
# ============================================================================

# MinIO storage backend configuration
MINIO_HOST = get_env("MINIO_HOST", default=get_env("MINIO_STORAGE_ENDPOINT", default="localhost:9000"))
MINIO_USE_HTTPS = get_env("MINIO_USE_HTTPS", default=False, cast=bool)
MINIO_ACCESS_KEY = get_env("MINIO_ACCESS_KEY", default=get_env("MINIO_STORAGE_ACCESS_KEY", default="minioadmin"))
MINIO_SECRET_KEY = get_env("MINIO_SECRET_KEY", default=get_env("MINIO_STORAGE_SECRET_KEY", default="minioadmin"))
MINIO_DEFAULT_BUCKET = get_env("MINIO_DEFAULT_BUCKET", default=get_env("MINIO_STORAGE_MEDIA_BUCKET_NAME", default="mylandlord-files"))
MINIO_STATIC_BUCKET = get_env("MINIO_STATIC_BUCKET", default=get_env("MINIO_STORAGE_STATIC_BUCKET_NAME", default=f"{MINIO_DEFAULT_BUCKET}-static"))
MINIO_CONSISTENCY_CHECK_ON_START = get_env("MINIO_CONSISTENCY_CHECK_ON_START", default=False, cast=bool)
MINIO_BUCKET_CHECK_ON_SAVE = get_env("MINIO_BUCKET_CHECK_ON_SAVE", default=True, cast=bool)

from datetime import timedelta
MINIO_URL_EXPIRY_HOURS = get_env("MINIO_URL_EXPIRY_HOURS", default=timedelta(days=1))

# Configure storage backends
STORAGES = {
    "default": {
        "BACKEND": "django_minio_backend.models.MinioBackend",
        "OPTIONS": {
            "MINIO_ENDPOINT": MINIO_HOST,
            "MINIO_ACCESS_KEY": MINIO_ACCESS_KEY,
            "MINIO_SECRET_KEY": MINIO_SECRET_KEY,
            "MINIO_USE_HTTPS": MINIO_USE_HTTPS,
            "MINIO_PRIVATE_BUCKETS": [MINIO_DEFAULT_BUCKET],
            "MINIO_PUBLIC_BUCKETS": [],
            "MINIO_DEFAULT_BUCKET": MINIO_DEFAULT_BUCKET,
            "MINIO_STATIC_FILES_BUCKET": MINIO_STATIC_BUCKET,
            "MINIO_CONSISTENCY_CHECK_ON_START": MINIO_CONSISTENCY_CHECK_ON_START,
            "MINIO_BUCKET_CHECK_ON_SAVE": MINIO_BUCKET_CHECK_ON_SAVE,
            "MINIO_URL_EXPIRY_HOURS": MINIO_URL_EXPIRY_HOURS,
        },
    },
    "staticfiles": {
        "BACKEND": "django_minio_backend.models.MinioBackendStatic",
        "OPTIONS": {
            "MINIO_ENDPOINT": MINIO_HOST,
            "MINIO_ACCESS_KEY": MINIO_ACCESS_KEY,
            "MINIO_SECRET_KEY": MINIO_SECRET_KEY,
            "MINIO_USE_HTTPS": MINIO_USE_HTTPS,
            "MINIO_STATIC_FILES_BUCKET": MINIO_STATIC_BUCKET,
            "MINIO_BUCKET_CHECK_ON_SAVE": MINIO_BUCKET_CHECK_ON_SAVE,
        },
    },
}

# Construct URLs from configured host/protocol so they adapt to env changes
MEDIA_URL = f"{'https' if MINIO_USE_HTTPS else 'http'}://{MINIO_HOST}/{MINIO_DEFAULT_BUCKET}/"
STATIC_URL = f"{'https' if MINIO_USE_HTTPS else 'http'}://{MINIO_HOST}/{MINIO_STATIC_BUCKET}/"

