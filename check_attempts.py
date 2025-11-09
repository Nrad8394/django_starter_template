#!/usr/bin/env python
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_starter_template.django_starter_template.settings')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'django_starter_template'))
django.setup()

from apps.accounts.models import LoginAttempt

def main():
    attempts = LoginAttempt.objects.all()
    print(f'Total login attempts: {attempts.count()}')
    for attempt in attempts[:5]:
        user_email = attempt.user.email if attempt.user else "No user"
        print(f'{user_email} - {attempt.successful} - {attempt.ip_address} - {attempt.timestamp}')

if __name__ == '__main__':
    main()