"""
Management command to initialize the accounts app with basic roles and permissions.
"""

from ast import Try
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from django.db import IntegrityError, models
from datetime import timedelta
from apps.accounts.models import UserRole, UserProfile
from apps.accounts.constants import ROLE_DEFINITIONS
from faker import Faker
import random
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Initialize the accounts app with roles, permissions, and sample data"

    def add_arguments(self, parser):
        parser.add_argument(
            "--sample-users",
            type=int,
            default=5,
            help="Number of sample users to create (default: 5)",
        )
        parser.add_argument(
            "--clear",
            action="store_true",
            help="Clear existing data before initializing",
        )
        parser.add_argument(
            "--skip-sample-data",
            action="store_true",
            help="Skip creating sample users, only create roles/permissions",
        )

    def handle(self, *args, **options):
        sample_users = options["sample_users"]
        clear_data = options["clear"]
        skip_sample_data = options["skip_sample_data"]

        self.stdout.write(self.style.NOTICE("Initializing accounts app..."))

        if clear_data:
            self.stdout.write("Clearing existing data...")
            self._clear_existing_data()

        # Step 1: Create custom permissions
        self._create_custom_permissions()

        # Step 2: Create default roles
        self._create_default_roles()

        # Step 3: Update role permissions
        self._update_role_permissions()

        # Step 4: Create default users for each role
        self._create_default_users()

        # if not skip_sample_data:
        #     # Step 5: Create sample data
        #     self._create_sample_data(sample_users)

        self.stdout.write(self.style.SUCCESS("Accounts app initialization completed!"))

    def _clear_existing_data(self):
        """Clear all existing accounts data"""
        try:
            UserProfile.objects.all().delete()
            User.objects.all().delete()
            UserRole.objects.all().delete()
            self.stdout.write("Cleared existing accounts data")
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"Error clearing data: {e}"))

    def _create_custom_permissions(self):
        """Create basic custom permissions for all modules"""
        self.stdout.write("Creating custom permissions...")

        # Get content types for accounts models
        user_ct = ContentType.objects.get_for_model(User)
        user_role_ct = ContentType.objects.get_for_model(UserRole)

        # Define basic permissions
        custom_permissions = [
            # User permissions
            (user_ct, "view_dashboard", "Can view dashboard"),
            (user_ct, "can_assign_roles", "Can assign roles to users"),
            (user_ct, "can_view_all_users", "Can view all users in the system"),
            (user_ct, "can_manage_permissions", "Can manage permissions"),
            (user_ct, "can_manage_roles", "Can manage roles"),
            (user_ct, "can_manage_users", "Can manage users"),
            (user_ct, "can_view_dashboard", "Can view dashboard"),
            # Module permissions
            (user_ct, "can_view_accounts_module", "Can view accounts module"),
            (user_ct, "can_view_security_module", "Can view security module"),
            # Role permissions
            (user_role_ct, "can_manage_roles", "Can manage user roles"),
        ]

        # Create permissions if they don't exist
        created_count = 0
        for content_type, codename, name in custom_permissions:
            permission, created = Permission.objects.get_or_create(
                codename=codename, content_type=content_type, defaults={"name": name}
            )

            if created:
                created_count += 1
                self.stdout.write(
                    f"  Created permission: {content_type.app_label}.{codename}"
                )

        self.stdout.write(
            self.style.SUCCESS(f"Created {created_count} custom permissions")
        )
        self.stdout.write(
            self.style.NOTICE(
                "Note: Standard Django permissions (view/add/change/delete) are auto-created for all models"
            )
        )

    def _create_default_roles(self):
        """Create default roles"""
        self.stdout.write("Creating default roles...")

        created_count = 0
        for role_name, role_data in ROLE_DEFINITIONS.items():
            role, created = UserRole.objects.get_or_create(
                name=role_name,
                defaults={
                    "display_name": role_data.get("display_name", role_name.title()),
                    "description": role_data["description"],
                    "is_active": True,
                },
            )

            if created:
                created_count += 1
                self.stdout.write(f"  Created role: {role_name}")

        self.stdout.write(self.style.SUCCESS(f"Created {created_count} roles"))

    def _update_role_permissions(self):
        """Update role permissions"""
        self.stdout.write("Updating role permissions...")

        for role_name, role_data in ROLE_DEFINITIONS.items():
            try:
                role = UserRole.objects.get(name=role_name)
                permissions = []

                # Get permissions for this role
                for perm_codename in role_data.get("permissions", []):
                    # Support codenames that include app label (e.g. "accounts.can_manage_users")
                    try:
                        if "." in perm_codename:
                            app_label, codename = perm_codename.split(".", 1)
                            qs = Permission.objects.filter(
                                codename=codename, content_type__app_label=app_label
                            )
                        else:
                            # Filter by codename only. There may be multiple permissions with same codename
                            qs = Permission.objects.filter(codename=perm_codename)

                        if not qs.exists():
                            self.stdout.write(
                                self.style.WARNING(
                                    f"  Permission {perm_codename} not found"
                                )
                            )
                        elif qs.count() == 1:
                            permissions.append(qs.first())
                        else:
                            # Multiple permissions found with same codename. Try to prefer the accounts app
                            preferred = qs.filter(
                                content_type__app_label="accounts"
                            ).first()
                            if preferred:
                                permissions.append(preferred)
                                self.stdout.write(
                                    self.style.WARNING(
                                        f"  Multiple permissions found for {perm_codename}; selected {preferred.content_type.app_label}.{preferred.codename}"
                                    )
                                )
                            else:
                                # Fall back to first and warn
                                permissions.append(qs.first())
                                self.stdout.write(
                                    self.style.WARNING(
                                        f"  Multiple permissions found for {perm_codename}; selected first match {qs.first().content_type.app_label}.{qs.first().codename}"
                                    )
                                )

                    except Exception as ex:
                        # Catch unexpected lookup errors and continue
                        self.stdout.write(
                            self.style.WARNING(
                                f"  Error resolving permission {perm_codename}: {ex}"
                            )
                        )

                # Update role permissions
                role.permissions.set(permissions)
                self.stdout.write(f"  Updated permissions for role: {role_name}")

            except UserRole.DoesNotExist:
                self.stdout.write(self.style.WARNING(f"  Role {role_name} not found"))

        self.stdout.write(self.style.SUCCESS("Role permissions updated"))

    def _create_default_users(self):
        """Create default users for each role"""
        self.stdout.write("Creating default users for each role...")

        # Define default users for each role
        default_users = {
            "admin": {
                "username": "admin",
                "email": "admin@gmail.com",
                "first_name": "Admin",
                "last_name": "User",
                "password": "user@12345",
                "is_staff": True,
                "is_superuser": True,
                "bio": "System Administrator",
            },
        }

        created_count = 0
        for role_name, user_data in default_users.items():
            try:
                role = UserRole.objects.get(name=role_name)
            except UserRole.DoesNotExist:
                self.stdout.write(
                    self.style.WARNING(
                        f"Role {role_name} not found, skipping user creation"
                    )
                )
                continue

            # Check if user already exists
            if User.objects.filter(email=user_data["email"]).exists():
                self.stdout.write(f"User for role {role_name} already exists")
                continue

            # Create user with role assigned immediately
            user = User.objects.create_user(
                username=user_data["username"],
                email=user_data["email"],
                password=user_data["password"],
                first_name=user_data["first_name"],
                last_name=user_data["last_name"],
                is_staff=user_data["is_staff"],
                is_superuser=user_data["is_superuser"],
                is_approved=True,
                is_verified=True,
                role=role,  # Assign role during creation (NOT NULL constraint)
            )

            # Update user profile (created by signal)
            user.profile.bio = user_data["bio"]
            user.profile.preferred_language = "en"
            user.profile.save()

            created_count += 1
            self.stdout.write(
                f'  Created user for role: {role_name} ({user_data["email"]})'
            )

        self.stdout.write(self.style.SUCCESS(f"Created {created_count} default users"))

