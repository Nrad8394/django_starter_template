from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.core.management import get_commands, load_command_class
import sys
import os
from django.conf import settings


class Command(BaseCommand):
    help = 'Populate all apps with sample data by calling individual populate_data commands'

    def add_arguments(self, parser):
        parser.add_argument(
            '--apps',
            nargs='*',
            help='Specific apps to populate (default: all apps with populate_data command)'
        )
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing data before populating'
        )
        parser.add_argument(
            '--count',
            type=int,
            default=10,
            help='Default number of items to create per app (default: 10)'
        )

    def handle(self, *args, **options):
        self.stdout.write('Starting population of all apps...')

        # Define apps that have populate_data commands
        # This is a template - customize based on your project's apps
        apps_with_populate = [
            'accounts',  # If you have an accounts app
            # Add other apps here as you create them
        ]

        # Filter by specified apps if provided
        if options['apps']:
            specified_apps = set(options['apps'])
            apps_with_populate = [
                app for app in apps_with_populate
                if app in specified_apps
            ]

        if not apps_with_populate:
            self.stdout.write(
                self.style.WARNING('No apps specified or found with populate_data commands.')
            )
            self.stdout.write('This is normal for a fresh Django starter template.')
            self.stdout.write('Add apps to the apps_with_populate list as you create them.')
            return

        self.stdout.write(f'Found {len(apps_with_populate)} apps with populate_data commands:')
        for app in apps_with_populate:
            self.stdout.write(f'  - {app}')

        # Execute populate commands in order
        # Define execution order to handle dependencies
        execution_order = apps_with_populate  # Simple order for template

        self.stdout.write('\nExecuting populate commands...')

        successful_apps = []
        failed_apps = []

        for app_name in execution_order:
            self.stdout.write(f'\n{self.style.SUCCESS("→")} Populating {app_name}...')

            try:
                # Import and run the specific populate_data command for this app
                module_path = f'apps.{app_name}.management.commands.populate_data'
                module = __import__(module_path, fromlist=['Command'])
                command_class = module.Command
                command_instance = command_class()
                # Create a mock options dict for the command
                from argparse import Namespace
                options_ns = Namespace()
                options_ns.clear = options['clear']
                options_ns.count = self.get_app_count(app_name, options['count'])
                command_instance.handle(*[], **vars(options_ns))

                successful_apps.append(app_name)
                self.stdout.write(
                    self.style.SUCCESS(f'✓ Successfully populated {app_name}')
                )

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'✗ Failed to populate {app_name}: {str(e)}')
                )
                failed_apps.append((app_name, str(e)))

        # Summary
        self.stdout.write('\n' + '='*50)
        self.stdout.write('POPULATION SUMMARY')
        self.stdout.write('='*50)

        if successful_apps:
            self.stdout.write(f'{self.style.SUCCESS("✓")} Successfully populated {len(successful_apps)} apps:')
            for app in successful_apps:
                self.stdout.write(f'  - {app}')

        if failed_apps:
            self.stdout.write(f'{self.style.ERROR("✗")} Failed to populate {len(failed_apps)} apps:')
            for app, error in failed_apps:
                self.stdout.write(f'  - {app}: {error}')

        if successful_apps and not failed_apps:
            self.stdout.write(
                self.style.SUCCESS('\n🎉 All apps populated successfully!')
            )
        elif successful_apps:
            self.stdout.write(
                self.style.WARNING(f'\n⚠️  Partially successful: {len(successful_apps)}/{len(successful_apps) + len(failed_apps)} apps populated')
            )
        else:
            self.stdout.write(
                self.style.ERROR('\n❌ No apps were populated successfully')
            )

    def get_app_count(self, app_name, default_count):
        """
        Get the appropriate count for each app.
        Some apps might need different amounts of data.
        """
        app_counts = {
            'accounts': max(default_count, 5),  # Need at least some users
        }
        return app_counts.get(app_name, default_count)