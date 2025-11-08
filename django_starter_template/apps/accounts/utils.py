"""
Utility functions for the accounts app
"""
import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta


def validate_employee_id(employee_id):
    """
    Validate employee ID format
    """
    if not employee_id:
        return

    # Basic validation - alphanumeric with optional hyphens
    if not re.match(r'^[A-Za-z0-9-]+$', employee_id):
        raise ValidationError(_("Employee ID can only contain letters, numbers, and hyphens"))

    # Check length
    if len(employee_id) < 2 or len(employee_id) > 50:
        raise ValidationError(_("Employee ID must be between 2 and 50 characters"))


def validate_phone_number(phone_number):
    """
    Validate phone number format
    """
    if not phone_number:
        return

    # Basic phone number validation - allow international formats
    # Remove spaces, hyphens, parentheses for validation
    cleaned = re.sub(r'[\s\-\(\)]', '', phone_number)

    # Must contain only digits and optional + at start
    if not re.match(r'^\+?\d+$', cleaned):
        raise ValidationError(_("Phone number can only contain digits, spaces, hyphens, parentheses, and +"))

    # Reasonable length check
    if len(cleaned) < 7 or len(cleaned) > 15:
        raise ValidationError(_("Phone number must be between 7 and 15 digits"))


def get_client_ip(request):
    """
    Get client IP address from request, handling proxy headers
    """
    if not request:
        return None

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Get the first IP in case of multiple proxies
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '')
    return ip


def calculate_password_strength(password):
    """
    Calculate password strength score (0-5)
    """
    score = 0

    # Length check
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1

    # Character variety
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[0-9]', password):
        score += 1
    if re.search(r'[^a-zA-Z0-9]', password):
        score += 1

    return min(score, 5)


def is_password_strong(password):
    """
    Check if password meets minimum strength requirements
    """
    return calculate_password_strength(password) >= 3


def generate_username_from_email(email):
    """
    Generate a username from email address
    """
    if not email:
        return None

    # Take part before @ and make it lowercase
    username = email.split('@')[0].lower()

    # Remove non-alphanumeric characters except underscore and dot
    username = re.sub(r'[^a-zA-Z0-9_.]', '', username)

    # Ensure minimum length
    if len(username) < 3:
        username = f"user_{username}"

    return username


def get_user_display_name(user):
    """
    Get display name for user (full name or email)
    """
    if hasattr(user, 'get_full_name') and user.get_full_name():
        return user.get_full_name()
    return user.email if hasattr(user, 'email') else str(user)


def check_account_lockout_expiry(user):
    """
    Check if account lockout has expired and reset if needed
    """
    if hasattr(user, 'account_locked_until') and user.account_locked_until:
        if user.account_locked_until <= timezone.now():
            # Lock expired, reset counters
            user.account_locked_until = None
            user.failed_login_attempts = 0
            user.save(update_fields=['account_locked_until', 'failed_login_attempts'])
            return True  # Was locked but now reset
        return False  # Still locked
    return True  # Not locked


def get_lockout_remaining_time(user):
    """
    Get remaining lockout time in minutes
    """
    if hasattr(user, 'account_locked_until') and user.account_locked_until:
        if user.account_locked_until > timezone.now():
            remaining = user.account_locked_until - timezone.now()
            return int(remaining.total_seconds() // 60)
    return 0


def cleanup_expired_sessions():
    """
    Clean up expired user sessions
    """
    from .models import UserSession

    expired_count = UserSession.objects.filter(
        expires_at__lt=timezone.now(),
        is_active=True
    ).update(is_active=False)

    return expired_count


def get_active_sessions_count(user):
    """
    Get count of active sessions for a user
    """
    from .models import UserSession

    return UserSession.objects.filter(
        user=user,
        is_active=True,
        expires_at__gt=timezone.now()
    ).count()