"""
Storage Configuration for the Application
==========================================

This module contains configurations for all storage backends including:
- MinIO/S3-compatible object storage
- Redis caching and message queuing
- Storage factory and backend management
"""

import os
from enum import Enum
from redis import Redis
import logging
from decouple import config

logger = logging.getLogger(__name__)


# =============================================================================
# STORAGE BACKEND TYPES
# =============================================================================

class StorageBackend(Enum):
    """Storage backend types"""
    MINIO = "minio"
    S3 = "s3"
    AZURE = "azure"
    LOCAL = "local"


# =============================================================================
# GENERIC STORAGE INTERFACE
# =============================================================================

class BaseStorage:
    """
    Base storage interface for all storage backends
    """

    def __init__(self):
        self.endpoint = None
        self.access_key = None
        self.secret_key = None
        self.secure = False
        self.region = None

    def connect(self):
        """Establish connection to storage backend"""
        raise NotImplementedError("Subclasses must implement connect()")

    def upload_file(self, bucket: str, key: str, file_path: str) -> str:
        """Upload file to storage"""
        raise NotImplementedError("Subclasses must implement upload_file()")

    def download_file(self, bucket: str, key: str, file_path: str) -> bool:
        """Download file from storage"""
        raise NotImplementedError("Subclasses must implement download_file()")

    def delete_file(self, bucket: str, key: str) -> bool:
        """Delete file from storage"""
        raise NotImplementedError("Subclasses must implement delete_file()")

    def file_exists(self, bucket: str, key: str) -> bool:
        """Check if file exists in storage"""
        raise NotImplementedError("Subclasses must implement file_exists()")

    def get_file_url(self, bucket: str, key: str, expires: int = 3600) -> str:
        """Get presigned URL for file"""
        raise NotImplementedError("Subclasses must implement get_file_url()")


class MinioStorage(BaseStorage):
    """
    MinIO/S3-compatible storage implementation
    """

    def __init__(self):
        super().__init__()
        self.endpoint = MINIO_ENDPOINT
        self.access_key = MINIO_ACCESS_KEY
        self.secret_key = MINIO_SECRET_KEY
        self.secure = MINIO_SECURE
        self.region = MINIO_REGION
        self.client = None

    def connect(self):
        """Establish MinIO connection"""
        try:
            from minio import Minio
            self.client = Minio(
                endpoint=self.endpoint,
                access_key=self.access_key,
                secret_key=self.secret_key,
                secure=self.secure,
                region=self.region
            )
            logger.info(f"Connected to MinIO at {self.endpoint}")
        except ImportError:
            logger.error("MinIO package not installed. Install with: pip install minio")
            raise
        except Exception as e:
            logger.error(f"Failed to connect to MinIO: {e}")
            raise

    def upload_file(self, bucket: str, key: str, file_path: str) -> str:
        """Upload file to MinIO"""
        if not self.client:
            self.connect()

        try:
            # Ensure bucket exists
            if not self.client.bucket_exists(bucket):
                self.client.make_bucket(bucket)
                logger.info(f"Created bucket: {bucket}")

            # Upload file
            self.client.fput_object(bucket, key, file_path)
            logger.info(f"Uploaded file {file_path} to {bucket}/{key}")
            return f"{bucket}/{key}"
        except Exception as e:
            logger.error(f"Failed to upload file {file_path}: {e}")
            raise

    def download_file(self, bucket: str, key: str, file_path: str) -> bool:
        """Download file from MinIO"""
        if not self.client:
            self.connect()

        try:
            self.client.fget_object(bucket, key, file_path)
            logger.info(f"Downloaded {bucket}/{key} to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to download {bucket}/{key}: {e}")
            return False

    def delete_file(self, bucket: str, key: str) -> bool:
        """Delete file from MinIO"""
        if not self.client:
            self.connect()

        try:
            self.client.remove_object(bucket, key)
            logger.info(f"Deleted {bucket}/{key}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete {bucket}/{key}: {e}")
            return False

    def file_exists(self, bucket: str, key: str) -> bool:
        """Check if file exists in MinIO"""
        if not self.client:
            self.connect()

        try:
            self.client.stat_object(bucket, key)
            return True
        except Exception:
            return False

    def get_file_url(self, bucket: str, key: str, expires: int = 3600) -> str:
        """Get presigned URL for MinIO file"""
        if not self.client:
            self.connect()

        try:
            url = self.client.presigned_get_object(bucket, key, expires=expires)
            return url
        except Exception as e:
            logger.error(f"Failed to get presigned URL for {bucket}/{key}: {e}")
            raise


class S3Storage(BaseStorage):
    """
    AWS S3 storage implementation
    """

    def __init__(self):
        super().__init__()
        # S3 specific configuration would go here
        logger.warning("S3 storage backend not yet implemented")

    def connect(self):
        """Establish S3 connection"""
        raise NotImplementedError("S3 storage backend not yet implemented")

    def upload_file(self, bucket: str, key: str, file_path: str) -> str:
        raise NotImplementedError("S3 storage backend not yet implemented")

    def download_file(self, bucket: str, key: str, file_path: str) -> bool:
        raise NotImplementedError("S3 storage backend not yet implemented")

    def delete_file(self, bucket: str, key: str) -> bool:
        raise NotImplementedError("S3 storage backend not yet implemented")

    def file_exists(self, bucket: str, key: str) -> bool:
        raise NotImplementedError("S3 storage backend not yet implemented")

    def get_file_url(self, bucket: str, key: str, expires: int = 3600) -> str:
        raise NotImplementedError("S3 storage backend not yet implemented")


class AzureStorage(BaseStorage):
    """
    Azure Blob storage implementation
    """

    def __init__(self):
        super().__init__()
        # Azure specific configuration would go here
        logger.warning("Azure storage backend not yet implemented")

    def connect(self):
        """Establish Azure connection"""
        raise NotImplementedError("Azure storage backend not yet implemented")

    def upload_file(self, bucket: str, key: str, file_path: str) -> str:
        raise NotImplementedError("Azure storage backend not yet implemented")

    def download_file(self, bucket: str, key: str, file_path: str) -> bool:
        raise NotImplementedError("Azure storage backend not yet implemented")

    def delete_file(self, bucket: str, key: str) -> bool:
        raise NotImplementedError("Azure storage backend not yet implemented")

    def file_exists(self, bucket: str, key: str) -> bool:
        raise NotImplementedError("Azure storage backend not yet implemented")

    def get_file_url(self, bucket: str, key: str, expires: int = 3600) -> str:
        raise NotImplementedError("Azure storage backend not yet implemented")


class LocalStorage(BaseStorage):
    """
    Local file system storage implementation
    """

    def __init__(self):
        super().__init__()
        self.base_path = os.path.join(os.getcwd(), 'storage')
        os.makedirs(self.base_path, exist_ok=True)
        logger.info(f"Local storage initialized at: {self.base_path}")

    def connect(self):
        """Local storage doesn't need connection"""
        pass

    def upload_file(self, bucket: str, key: str, file_path: str) -> str:
        """Copy file to local storage"""
        bucket_path = os.path.join(self.base_path, bucket)
        os.makedirs(bucket_path, exist_ok=True)

        dest_path = os.path.join(bucket_path, key)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        import shutil
        shutil.copy2(file_path, dest_path)
        logger.info(f"Copied {file_path} to {dest_path}")
        return f"{bucket}/{key}"

    def download_file(self, bucket: str, key: str, file_path: str) -> bool:
        """Copy file from local storage"""
        source_path = os.path.join(self.base_path, bucket, key)

        if not os.path.exists(source_path):
            logger.error(f"File not found: {source_path}")
            return False

        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        import shutil
        shutil.copy2(source_path, file_path)
        logger.info(f"Copied {source_path} to {file_path}")
        return True

    def delete_file(self, bucket: str, key: str) -> bool:
        """Delete file from local storage"""
        file_path = os.path.join(self.base_path, bucket, key)

        if not os.path.exists(file_path):
            logger.warning(f"File not found for deletion: {file_path}")
            return False

        os.remove(file_path)
        logger.info(f"Deleted {file_path}")
        return True

    def file_exists(self, bucket: str, key: str) -> bool:
        """Check if file exists in local storage"""
        file_path = os.path.join(self.base_path, bucket, key)
        return os.path.exists(file_path)

    def get_file_url(self, bucket: str, key: str, expires: int = 3600) -> str:
        """Get local file path as URL"""
        file_path = os.path.join(self.base_path, bucket, key)
        if os.path.exists(file_path):
            # Return file:// URL for local files
            return f"file://{os.path.abspath(file_path)}"
        else:
            raise FileNotFoundError(f"File not found: {file_path}")


# =============================================================================
# MINIO OBJECT STORAGE CONFIGURATION
# =============================================================================

# MinIO/S3 Configuration
MINIO_ENDPOINT = config("MINIO_ENDPOINT", default="localhost:9000")
MINIO_ACCESS_KEY = config("MINIO_ACCESS_KEY", default="minioadmin")
MINIO_SECRET_KEY = config("MINIO_SECRET_KEY", default="minioadmin")
MINIO_SECURE = config("MINIO_SECURE", default="false", cast=bool)
MINIO_REGION = config("MINIO_REGION", default="us-east-1")

# Storage Implementation
STORAGE_BACKEND = config("STORAGE_BACKEND", default="MINIO").upper()

# Bucket configurations
DEFAULT_BUCKET = "documents"
MEDIA_BUCKET = "media"
BACKUP_BUCKET = "backups"

# =============================================================================
# REDIS CONFIGURATION
# =============================================================================

# Redis Connection Settings
REDIS_HOST = config("REDIS_HOST", default="localhost")
REDIS_PORT = config("REDIS_PORT", default=6379, cast=int)
REDIS_DB = config("REDIS_DB", default=1, cast=int)  # DB 1 for RAG, DB 0 for Celery
REDIS_PASSWORD = config("REDIS_PASSWORD", default=None)
REDIS_SSL = config("REDIS_SSL", default="false", cast=bool)

# Redis URLs for different purposes
REDIS_URL = f"redis://{'localhost' if REDIS_HOST == 'localhost' else REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
if REDIS_PASSWORD:
    REDIS_URL = f"redis://:{REDIS_PASSWORD}@{'localhost' if REDIS_HOST == 'localhost' else REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"

# =============================================================================
# STORAGE FACTORY
# =============================================================================

class StorageFactory:
    """
    Factory pattern for storage backend instantiation
    """

    storage_mapping = {
        StorageBackend.MINIO: "Minio",
        StorageBackend.S3: "S3",
        StorageBackend.AZURE: "Azure",
        StorageBackend.LOCAL: "Local"
    }

    @classmethod
    def create(cls, storage_type: StorageBackend):
        """
        Creates storage instance based on type

        Args:
            storage_type: StorageBackend enum value

        Returns:
            Storage implementation instance
        """
        class_map = {
            StorageBackend.MINIO: MinioStorage,
            StorageBackend.S3: S3Storage,
            StorageBackend.AZURE: AzureStorage,
            StorageBackend.LOCAL: LocalStorage,
        }

        storage_class = class_map.get(storage_type)
        if not storage_class:
            raise ValueError(f"Unsupported storage type: {storage_type}. Available: {list(class_map.keys())}")

        logger.info(f"Initializing storage backend: {storage_type.value}")
        instance = storage_class()
        instance.connect()  # Auto-connect on instantiation
        return instance

    @classmethod
    def create_from_settings(cls):
        """
        Creates storage instance from settings

        Returns:
            Storage implementation instance
        """
        storage_type_str = STORAGE_BACKEND

        try:
            storage_type = StorageBackend[storage_type_str]
        except KeyError:
            logger.warning(f"Unknown storage type '{storage_type_str}', defaulting to MINIO")
            storage_type = StorageBackend.MINIO

        return cls.create(storage_type)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_storage_impl():
    """
    Get storage implementation instance

    Returns:
        Storage backend instance based on settings
    """
    storage_impl_type = STORAGE_BACKEND

    try:
        storage_type = StorageBackend[storage_impl_type]
    except KeyError:
        logger.warning(f"Unknown STORAGE_BACKEND '{storage_impl_type}', defaulting to MINIO")
        storage_type = StorageBackend.MINIO

    return StorageFactory.create(storage_type)


def get_redis_connection():
    """
    Get Redis connection instance

    Returns:
        Redis connection instance
    """
    return Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD,
        ssl=REDIS_SSL,
        decode_responses=True
    )


# =============================================================================
# DJANGO STORAGE CONFIGURATION
# =============================================================================

# MinIO Storage Configuration for Django
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "minioadmin")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "minioadmin")
AWS_STORAGE_BUCKET_NAME = os.getenv("MINIO_MEDIA_BUCKET", "media")
AWS_S3_ENDPOINT_URL = f"http://{os.getenv('MINIO_ENDPOINT', 'localhost:9000')}"
AWS_S3_CUSTOM_DOMAIN = os.getenv('AWS_S3_CUSTOM_DOMAIN')
AWS_LOCATION = 'media'
AWS_DEFAULT_ACL = None
AWS_S3_SIGNATURE_VERSION = 's3v4'
AWS_S3_REGION_NAME = 'us-east-1'

# Configure custom storage
AWS_S3_OBJECT_PARAMETERS = {
    'CacheControl': 'max-age=86400',
}

# Custom MinIO Storage with public URL generation
try:
    # Only import boto3-dependent S3Storage if boto3 is available
    import boto3
    from storages.backends.s3 import S3Storage

    class PublicMinIOStorage(S3Storage):
        """
        Custom S3Storage that generates public URLs while using internal MinIO endpoint
        """
        def url(self, name, parameters=None, expire=None, http_method=None):
            """
            Generate URL with public domain instead of internal MinIO endpoint
            """
            custom_domain = getattr(self, 'custom_domain', None)
            if custom_domain:
                protocol = 'https' if getattr(self, 'secure_urls', True) else 'http'
                url = f"{protocol}://{custom_domain}"
                if self.location:
                    url += f"/{self.location}/{name}"
                else:
                    url += f"/{name}"
                return url

            return super().url(name, parameters, expire, http_method)

    S3_AVAILABLE = True

except ImportError:
    logger.warning("boto3 or django-storages S3 backend not available. S3/MinIO storage disabled.")
    PublicMinIOStorage = None
    S3_AVAILABLE = False

# Configure custom storage
if os.getenv('AWS_S3_CUSTOM_DOMAIN') and PublicMinIOStorage and S3_AVAILABLE:
    PublicMinIOStorage.custom_domain = os.getenv('AWS_S3_CUSTOM_DOMAIN')

# Django STORAGES configuration
if PublicMinIOStorage and S3_AVAILABLE:
    STORAGES = {
        "default": {
            "BACKEND": "django_starter_template.settingsConfig.storage.PublicMinIOStorage",
        },
        "staticfiles": {
            "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
        },
    }
else:
    STORAGES = {
        "default": {
            "BACKEND": "django.core.files.storage.FileSystemStorage",
        },
        "staticfiles": {
            "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
        },
    }
