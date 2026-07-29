"""
Orchestrate every app's initialize/setup command.

Two things this got wrong and now does not.

**It listed apps that are not installed.** The registry below was a literal
dict, so ``apps.notifications`` — disabled deliberately, see
``settingsConfig/core/apps.py`` — was announced as one of three apps to
initialize and then reported as a red failure ("Unknown command:
'initialize_notifications'") on every single run. A command that cannot be
called because its app is switched off is a *skip* with a reason, not an
error. Entries are now checked against the app registry and Django's
command registry before they are attempted.

**It ignored its own ``--clear`` flag and hard-coded ``clear=True``.** That
made ``initialize_accounts`` run ``User.objects.all().delete()`` on every
invocation. The flag is now passed through, and the destructive path in
``initialize_accounts`` gained its own guards.

Also: the exit status is now non-zero when something failed, so this can be
used in a deploy script without silently succeeding.
"""

import logging
import time

from django.apps import apps as django_apps
from django.core.management import call_command, get_commands
from django.core.management.base import BaseCommand, CommandError
from django.db.utils import OperationalError

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = (
        "Initialize all apps in the project with their default data and configurations"
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--apps",
            nargs="*",
            help="Specific apps to initialize (default: all available apps)",
        )
        parser.add_argument(
            "--clear",
            action="store_true",
            help="Clear existing data before initializing",
        )
        parser.add_argument(
            "--skip-sample-data",
            action="store_true",
            help="Skip creating sample data, only create essential configurations",
        )
        parser.add_argument(
            "--sample-users",
            type=int,
            default=0,
            help=(
                "Number of sample users to create (default: 0 — none). "
                "Development only; initialize_accounts refuses outside DEBUG."
            ),
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Passed through to sub-commands; allows destructive steps outside DEBUG",
        )
        parser.add_argument(
            "--noinput",
            "--no-input",
            action="store_true",
            dest="noinput",
            help="Do not prompt for confirmation before a destructive step",
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS("🚀 Starting unified app initialization...")
        )

        # 0 means zero. The previous version rewrote 0 to 5, so the documented
        # default — and an explicit `--sample-users 0` — both silently created
        # five accounts nobody asked for.
        sample_users = options["sample_users"]

        # Registry. `app_label` is what decides whether an entry is live: an
        # app that is not installed has no commands registered, so attempting
        # its command can only ever produce a confusing error.
        registry = {
            "accounts": {
                "app_label": "accounts",
                "command": "initialize_accounts",
                "description": "Initialize user roles, permissions, and the admin user",
                "options": {
                    "sample_users": sample_users,
                    # Pass the flag through instead of hard-coding True. This
                    # one line used to delete every user in the database.
                    "clear": options["clear"],
                    "skip_sample_data": options["skip_sample_data"],
                    "force": options["force"],
                    "noinput": options["noinput"],
                },
            },
            "notifications": {
                "app_label": "notifications",
                "command": "initialize_notifications",
                "description": "Initialize notification templates, events, and configurations",
                "options": {},
            },
            "security": {
                "app_label": "security",
                "command": "setup_security",
                "description": "Configure security settings and policies",
                "options": {},
            },
        }

        # Filter apps if specified
        if options["apps"]:
            specified_apps = set(options["apps"])
            unknown = specified_apps - set(registry)
            if unknown:
                raise CommandError(
                    f"Unknown app(s): {', '.join(sorted(unknown))}. "
                    f"Known: {', '.join(sorted(registry))}."
                )
            registry = {
                app: config for app, config in registry.items() if app in specified_apps
            }

        available_commands = get_commands()
        app_commands, skipped = {}, []
        for app_name, config in registry.items():
            if not django_apps.is_installed(f"apps.{config['app_label']}"):
                skipped.append((app_name, "app is not in INSTALLED_APPS"))
            elif config["command"] not in available_commands:
                skipped.append(
                    (app_name, f"no management command named '{config['command']}'")
                )
            else:
                app_commands[app_name] = config

        if not app_commands and not skipped:
            self.stdout.write(
                self.style.WARNING("No valid apps specified for initialization.")
            )
            return

        self.stdout.write(f"Found {len(app_commands)} apps to initialize:")
        for app_name, config in app_commands.items():
            self.stdout.write(f'  • {app_name}: {config["description"]}')

        for app_name, reason in skipped:
            self.stdout.write(self.style.WARNING(f"  ⏭️ {app_name}: skipped — {reason}"))

        # Execute initialization commands in dependency order
        # Prefer initializing notifications early so other apps (accounts, etc.) can
        # safely reference templates / events during their own initialization.
        execution_order = [
            "notifications",
            "accounts",
            "security",
        ]  # Define dependency order
        ordered_apps = [app for app in execution_order if app in app_commands]

        self.stdout.write(f'\n📋 Initialization order: {" → ".join(ordered_apps)}')

        successful_apps = []
        failed_apps = []

        for app_name in ordered_apps:
            config = app_commands[app_name]
            self.stdout.write(f'\n{self.style.SUCCESS("⚙️")} Initializing {app_name}...')

            try:
                # Call the specific command for this app with a small retry loop to handle transient DB locks
                command_options = config["options"].copy()
                max_retries = 3
                for attempt in range(1, max_retries + 1):
                    try:
                        call_command(config["command"], **command_options)
                        break
                    except OperationalError:
                        if attempt < max_retries:
                            wait = 0.5 * attempt
                            self.stdout.write(
                                self.style.WARNING(
                                    f"  Database busy (attempt {attempt}/{max_retries}), retrying in {wait}s..."
                                )
                            )
                            time.sleep(wait)
                            continue
                        else:
                            raise

                successful_apps.append(app_name)
                self.stdout.write(
                    self.style.SUCCESS(f"✅ Successfully initialized {app_name}")
                )

            except Exception as e:
                error_msg = str(e)
                self.stdout.write(
                    self.style.ERROR(f"❌ Failed to initialize {app_name}: {error_msg}")
                )
                failed_apps.append((app_name, error_msg))
                logger.error(f"Failed to initialize {app_name}: {error_msg}")

        # Summary
        self.stdout.write("\n" + "=" * 70)
        self.stdout.write(self.style.SUCCESS("📊 INITIALIZATION SUMMARY"))
        self.stdout.write("=" * 70)

        if successful_apps:
            self.stdout.write(
                f'{self.style.SUCCESS("✅")} Successfully initialized {len(successful_apps)} apps:'
            )
            for app in successful_apps:
                self.stdout.write(f"   • {app}")

        if skipped:
            self.stdout.write(f'{self.style.WARNING("⏭️")} Skipped {len(skipped)} apps:')
            for app, reason in skipped:
                self.stdout.write(f"   • {app}: {reason}")

        if failed_apps:
            self.stdout.write(
                f'{self.style.ERROR("❌")} Failed to initialize {len(failed_apps)} apps:'
            )
            for app, error in failed_apps:
                self.stdout.write(f"   • {app}: {error}")

        self.stdout.write("=" * 70)

        # Final status. A skip is not a failure — the app was never meant to
        # run — so a run with skips but no errors is a clean run.
        if failed_apps:
            raise CommandError(
                f"{len(failed_apps)} of "
                f"{len(successful_apps) + len(failed_apps)} apps failed to "
                "initialize. See the errors above."
            )

        self.stdout.write(
            self.style.SUCCESS("\n🎉 All available apps initialized successfully!")
        )
