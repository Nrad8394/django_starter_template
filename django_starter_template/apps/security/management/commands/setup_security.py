from django.core.management.base import BaseCommand
from django.utils.translation import gettext_lazy as _
from apps.security.models import SecuritySettings


class Command(BaseCommand):
    help = 'Set up initial security settings'

    def handle(self, *args, **options):
        self.stdout.write('Setting up security settings...')

        # Default security settings
        settings_data = [
            {
                'setting_type': SecuritySettings.SettingType.RATE_LIMIT,
                'name': 'Default Rate Limiting',
                'description': 'Rate limiting for general API endpoints',
                'config': {
                    'enabled': True,
                    'requests_per_minute': 100,
                    'requests_per_hour': 1000,
                    'block_duration_minutes': 15,
                }
            },
            {
                'setting_type': SecuritySettings.SettingType.RATE_LIMIT,
                'name': 'Authentication Rate Limiting',
                'description': 'Stricter rate limiting for authentication endpoints',
                'config': {
                    'enabled': True,
                    'requests_per_5_minutes': 5,
                    'requests_per_hour': 20,
                    'block_duration_minutes': 30,
                }
            },
            {
                'setting_type': SecuritySettings.SettingType.PASSWORD_POLICY,
                'name': 'Password Policy',
                'description': 'Password requirements and security policies',
                'config': {
                    'enabled': True,
                    'min_length': 8,
                    'require_uppercase': True,
                    'require_lowercase': True,
                    'require_digits': True,
                    'require_special_chars': True,
                    'max_age_days': 90,
                    'prevent_reuse_count': 5,
                }
            },
            {
                'setting_type': SecuritySettings.SettingType.SESSION_POLICY,
                'name': 'Session Policy',
                'description': 'Session management and security settings',
                'config': {
                    'enabled': True,
                    'timeout_minutes': 480,  # 8 hours
                    'idle_timeout_minutes': 120,  # 2 hours
                    'max_concurrent_sessions': 3,
                    'force_logout_on_password_change': True,
                }
            },
            {
                'setting_type': SecuritySettings.SettingType.ENCRYPTION,
                'name': 'Data Encryption',
                'description': 'Encryption settings for sensitive data',
                'config': {
                    'enabled': True,
                    'algorithm': 'AES256',
                    'key_rotation_days': 365,
                    'encrypt_fields': ['password', 'api_key', 'token', 'secret'],
                }
            },
            {
                'setting_type': SecuritySettings.SettingType.AUDIT,
                'name': 'Audit Logging',
                'description': 'Audit logging configuration',
                'config': {
                    'enabled': True,
                    'log_auth_events': True,
                    'log_data_modifications': True,
                    'log_api_access': True,
                    'retention_days': 365,
                    'sensitive_fields_redaction': True,
                }
            }
        ]

        for setting_data in settings_data:
            setting, created = SecuritySettings.objects.get_or_create(
                setting_type=setting_data['setting_type'],
                name=setting_data['name'],
                defaults={
                    'description': setting_data['description'],
                    'config': setting_data['config'],
                    'is_enabled': setting_data['config'].get('enabled', True)
                }
            )
            if created:
                self.stdout.write(f'Created security setting: {setting.name}')
            else:
                self.stdout.write(f'Security setting already exists: {setting.name}')

        self.stdout.write(
            self.style.SUCCESS('Successfully set up security settings')
        )