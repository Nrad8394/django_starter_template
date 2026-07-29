"""
Initialize the accounts app: permissions, roles, and the first admin user.

Safety notes, because this command deletes and creates credentials.

``--clear`` drops every user, profile and role in the database. It is
opt-in, refused outside ``DEBUG`` unless ``--force`` is given, and prompts
for confirmation unless ``--noinput``. It previously ran unconditionally:
``initialize_all_apps`` hard-coded ``clear=True`` while advertising a
``--clear`` flag it then ignored, so the documented "initialize" command
wiped the user table. It never fired only because an unused ``faker``
import raised first.

The admin user's credentials come from ``DJANGO_INIT_ADMIN_EMAIL`` and
``DJANGO_INIT_ADMIN_PASSWORD``. When the password is absent a random one is
generated and printed once. There is deliberately no default password in
this file: a committed superuser credential is a standing backdoor, and on
a system holding a political party's books that is not a theoretical one.
"""

import logging
import os
import secrets
import string

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.accounts.constants import ROLE_DEFINITIONS, UserRoleConstants
from apps.accounts.models import UserProfile, UserRole

User = get_user_model()
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Initialize the accounts app with roles, permissions, and an admin user"

    def add_arguments(self, parser):
        parser.add_argument(
            "--sample-users",
            type=int,
            default=0,
            help=(
                "Number of sample users to create (default: 0). Development "
                "only — refused unless DEBUG is on."
            ),
        )
        parser.add_argument(
            "--clear",
            action="store_true",
            help=(
                "DESTRUCTIVE. Delete every user, profile and role before "
                "initializing. Refused outside DEBUG unless --force."
            ),
        )
        parser.add_argument(
            "--skip-sample-data",
            action="store_true",
            help="Skip creating sample users, only create roles/permissions",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Allow --clear to run outside DEBUG. Use deliberately.",
        )
        parser.add_argument(
            "--noinput",
            "--no-input",
            action="store_true",
            dest="noinput",
            help="Do not prompt for confirmation before a destructive step.",
        )

    def handle(self, *args, **options):
        sample_users = options["sample_users"]
        skip_sample_data = options["skip_sample_data"]

        self.stdout.write(self.style.NOTICE("Initializing accounts app..."))

        if options["clear"]:
            self._clear_existing_data(force=options["force"], noinput=options["noinput"])

        # Step 1: Create custom permissions
        self._create_custom_permissions()

        # Step 2: Create default roles
        self._create_default_roles()

        # Step 3: Update role permissions
        self._update_role_permissions()

        # Step 4: Create the admin user
        self._create_default_users()

        # Step 5: Sample users, if asked for and only in development.
        if sample_users and not skip_sample_data:
            self._create_sample_data(sample_users)

        self.stdout.write(self.style.SUCCESS("Accounts app initialization completed!"))

    def _clear_existing_data(self, *, force: bool, noinput: bool):
        """
        Delete every user, profile and role.

        Guarded three ways because the blast radius is the whole user table
        and the command that calls this one used to do so silently.
        """
        if not settings.DEBUG and not force:
            raise CommandError(
                "--clear deletes every user, profile and role, and DEBUG is off. "
                "Re-run with --force if that is genuinely what you want."
            )

        count = User.objects.count()
        if not noinput:
            answer = input(
                f"This will delete {count} user(s), their profiles and all roles. "
                "This cannot be undone. Type 'yes' to continue: "
            )
            if answer.strip().lower() != "yes":
                raise CommandError("Aborted — nothing was deleted.")

        self.stdout.write(self.style.WARNING(f"Clearing {count} user(s) and all roles..."))
        # One transaction: a half-cleared user table (profiles gone, users
        # left) is worse than either end state.
        with transaction.atomic():
            UserProfile.objects.all().delete()
            User.objects.all().delete()
            UserRole.objects.all().delete()
        self.stdout.write("Cleared existing accounts data")

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
            # `can_manage_roles` belongs to UserRole (below), not User. It was
            # created on both content types, which is what produced the
            # "Multiple permissions found for can_manage_roles" warning on
            # every run — the ambiguity was self-inflicted.
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
            _permission, created = Permission.objects.get_or_create(
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
            _role, created = UserRole.objects.get_or_create(
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
        """
        Create the initial admin user.

        Credentials come from the environment, never from this file. The
        version this replaces hard-coded ``admin@gmail.com`` /
        ``user@12345`` with ``is_superuser=True`` — a published credential
        for full access to the party's books, created by a command whose
        name invites people to run it on a fresh production database.

        With no ``DJANGO_INIT_ADMIN_PASSWORD`` set, a random password is
        generated and printed once. It is never stored anywhere else, so
        capture it now or reset it later.
        """
        self.stdout.write("Creating the initial admin user...")

        email = os.environ.get("DJANGO_INIT_ADMIN_EMAIL", "").strip()
        if not email:
            if not settings.DEBUG:
                self.stdout.write(
                    self.style.WARNING(
                        "  DJANGO_INIT_ADMIN_EMAIL is not set and DEBUG is off — "
                        "skipping admin creation. Create the first superuser with "
                        "`manage.py createsuperuser`, which never writes a password "
                        "into a log or a source file."
                    )
                )
                return
            email = "admin@example.test"

        username = os.environ.get("DJANGO_INIT_ADMIN_USERNAME", "").strip() or "admin"
        password = os.environ.get("DJANGO_INIT_ADMIN_PASSWORD", "")
        generated = False
        if not password:
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
            password = "".join(secrets.choice(alphabet) for _ in range(20))
            generated = True

        try:
            role = UserRole.objects.get(name="admin")
        except UserRole.DoesNotExist:
            self.stdout.write(
                self.style.WARNING("Role 'admin' not found, skipping user creation")
            )
            return

        if User.objects.filter(email=email).exists():
            self.stdout.write(f"  Admin user already exists ({email}) — left untouched")
            return

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name="Admin",
            last_name="User",
            is_staff=True,
            is_superuser=True,
            is_approved=True,
            is_verified=True,
            role=role,  # Assign role during creation (NOT NULL constraint)
        )

        user.profile.bio = "System Administrator"
        user.profile.preferred_language = "en"
        user.profile.save()

        self.stdout.write(self.style.SUCCESS(f"  Created admin user: {email}"))
        if generated:
            # Printed, never logged: logger output is shipped and retained.
            self.stdout.write(
                self.style.WARNING(
                    f"  Generated password (shown once, not stored): {password}"
                )
            )

    def _create_sample_data(self, count: int):
        """
        Create ``count`` sample users for local development.

        Deliberately no `faker`: it was imported at module scope for this
        step, the step was never written, and the dead import broke the
        command in every image built without the test extras. Deterministic
        names cost nothing and keep a fake-data library out of the runtime
        image entirely.
        """
        if not settings.DEBUG:
            raise CommandError(
                "--sample-users creates fake accounts and DEBUG is off. Refusing: "
                "sample users on a live party system are indistinguishable from "
                "real ones once created."
            )

        # Prefer any non-admin role; sample accounts should not be superusers
        # even locally, because local databases get promoted more often than
        # anyone plans to.
        role = (
            UserRole.objects.exclude(name=UserRoleConstants.ADMIN).first()
            or UserRole.objects.first()
        )
        if role is None:
            self.stdout.write(
                self.style.WARNING("No roles exist, skipping sample users")
            )
            return

        self.stdout.write(f"Creating {count} sample user(s)...")
        created = 0
        for index in range(1, count + 1):
            email = f"sample{index}@example.test"
            if User.objects.filter(email=email).exists():
                continue
            User.objects.create_user(
                username=f"sample{index}",
                email=email,
                password=secrets.token_urlsafe(16),
                first_name="Sample",
                last_name=f"User {index}",
                is_approved=True,
                is_verified=True,
                role=role,
            )
            created += 1

        self.stdout.write(self.style.SUCCESS(f"Created {created} sample user(s)"))

