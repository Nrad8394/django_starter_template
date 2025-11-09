#!/usr/bin/env python
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_starter_template.settings')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'django_starter_template'))
django.setup()

from django.test import Client
from apps.accounts.models import LoginAttempt

def test_login_attempts():
    client = Client()

    print("Testing login attempt tracking...")

    # Check initial count
    initial_count = LoginAttempt.objects.count()
    print(f"Initial login attempts: {initial_count}")

    # Test failed login
    print("\nTesting failed login...")
    response = client.post('/api/v1/accounts/auth/login/', {
        'email': 'john.neal@example.com',
        'password': 'wrongpassword'
    }, content_type='application/json')
    print(f"Failed login response status: {response.status_code}")

    # Check count after failed login
    after_failed_count = LoginAttempt.objects.count()
    print(f"Login attempts after failed login: {after_failed_count}")

    # Test successful login
    print("\nTesting successful login...")
    response = client.post('/api/v1/accounts/auth/login/', {
        'email': 'john.neal@example.com',
        'password': 'password123!'
    }, content_type='application/json')
    print(f"Successful login response status: {response.status_code}")

    # Check final count
    final_count = LoginAttempt.objects.count()
    print(f"Final login attempts: {final_count}")

    # Show recent attempts
    attempts = LoginAttempt.objects.all().order_by('-created_at')[:5]
    print(f"\nRecent login attempts ({attempts.count()}):")
    for attempt in attempts:
        user_email = attempt.user.email if attempt.user else "No user"
        print(f"  {user_email} - Success: {attempt.success} - IP: {attempt.ip_address} - Time: {attempt.created_at}")

if __name__ == '__main__':
    test_login_attempts()