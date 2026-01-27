"""
Django management command to setup MinIO buckets and permissions.

This command:
1. Creates the media bucket if it doesn't exist
2. Sets the bucket policy to allow public read access
"""

import json
import os
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings


class Command(BaseCommand):
    help = "Setup MinIO buckets and configure permissions for public read access"

    def add_arguments(self, parser):
        parser.add_argument(
            '--noinput',
            action='store_true',
            dest='noinput',
            default=False,
            help='Run without user interaction (for automated deployment)',
        )

    def handle(self, *args, **options):
        try:
            from minio import Minio
            from minio.error import S3Error
        except ImportError:
            raise CommandError(
                "minio package is required. Install it with: pip install minio"
            )

        # Get MinIO configuration from settings
        endpoint = os.getenv("MINIO_ENDPOINT", "localhost:9000")
        access_key = os.getenv("AWS_ACCESS_KEY_ID", "minioadmin")
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", "minioadmin")
        bucket_name = os.getenv("MINIO_MEDIA_BUCKET", "media")
        secure = os.getenv("MINIO_SECURE", "false").lower() == "true"

        self.stdout.write(f"Connecting to MinIO at {endpoint}...")

        try:
            client = Minio(
                endpoint=endpoint,
                access_key=access_key,
                secret_key=secret_key,
                secure=secure,
            )

            # Check if bucket exists, create if not
            if not client.bucket_exists(bucket_name):
                self.stdout.write(f"Creating bucket '{bucket_name}'...")
                client.make_bucket(bucket_name)
                self.stdout.write(
                    self.style.SUCCESS(f"✓ Bucket '{bucket_name}' created")
                )
            else:
                self.stdout.write(f"Bucket '{bucket_name}' already exists")

            # Set bucket policy to allow public read access
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": [
                            "s3:GetObject",
                            "s3:GetObjectVersion",
                            "s3:ListBucket",
                            "s3:ListBucketVersions",
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{bucket_name}/*",
                            f"arn:aws:s3:::{bucket_name}",
                        ],
                    }
                ],
            }

            self.stdout.write(f"Setting bucket policy for '{bucket_name}'...")
            client.set_bucket_policy(bucket_name, json.dumps(policy))
            self.stdout.write(
                self.style.SUCCESS(f"✓ Bucket policy configured for public read access")
            )

            # Set CORS configuration on the bucket
            self.stdout.write(f"Setting CORS policy for '{bucket_name}'...")
            try:
                from minio.commonconfig import CORS, CorsRule
                
                cors_rule = CorsRule(
                    allowed_methods=["GET", "HEAD", "PUT", "POST", "DELETE"],
                    allowed_origins=["*"],
                    allowed_headers=["*"],
                    expose_headers=["ETag", "x-amz-version-id", "x-amz-request-id"],
                    max_age_seconds=3000,
                )
                client.set_bucket_cors(bucket_name, CORS([cors_rule]))
                self.stdout.write(
                    self.style.SUCCESS(f"✓ CORS policy configured for bucket")
                )
            except Exception as cors_error:
                # CORS configuration is not critical, warn but continue
                self.stdout.write(
                    self.style.WARNING(
                        f"⚠ Could not set CORS policy (non-critical): {cors_error}"
                    )
                )

            self.stdout.write(
                self.style.SUCCESS("\n✓ MinIO setup completed successfully!")
            )

        except S3Error as e:
            raise CommandError(f"MinIO error: {e}")
        except Exception as e:
            raise CommandError(f"Error setting up MinIO: {e}")
