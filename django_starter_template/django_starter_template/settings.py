import os

# Dynamically import the correct settings based on DJANGO_SETTINGS_MODULE
settings_module = os.environ.get('DJANGO_SETTINGS_MODULE', 'agex.settingsConfig.development')

if settings_module == 'agex.settingsConfig.production':
    from .settingsConfig.production import *
elif settings_module == 'agex.settingsConfig.test':
    from .settingsConfig.test import *
elif settings_module == 'agex.settingsConfig.development':
    from .settingsConfig.development import *
else:
    # Default to development settings if module is not recognized
    from .settingsConfig.development import *