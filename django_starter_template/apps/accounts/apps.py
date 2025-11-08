from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.accounts'
    label = 'accounts'  # This is what AUTH_USER_MODEL references
    verbose_name = 'Accounts'

    def ready(self):
        # Import signals here to ensure they are connected
        import apps.accounts.signals