from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.utils import timezone
from .models import AuditLog


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """Log successful user login"""
    AuditLog.objects.create(
        user=user,
        event_type=AuditLog.EventType.LOGIN,
        severity=AuditLog.Severity.LOW,
        description=f"User {user.get_username()} logged in successfully",
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT'),
        session_key=request.session.session_key,
        request_path=request.path,
        request_method=request.method,
    )


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    """Log user logout"""
    if not user:
        return
    
    AuditLog.objects.create(
        user=user,
        event_type=AuditLog.EventType.LOGOUT,
        severity=AuditLog.Severity.LOW,
        description=f"User {user.get_username()} logged out",
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT'),
        session_key=request.session.session_key,
        request_path=request.path,
        request_method=request.method,
    )


@receiver(user_login_failed)
def log_failed_login(sender, credentials, request, **kwargs):
    """Log failed login attempts"""
    username = credentials.get('username', 'unknown')
    AuditLog.objects.create(
        event_type=AuditLog.EventType.FAILED_LOGIN,
        severity=AuditLog.Severity.MEDIUM,
        description=f"Failed login attempt for username: {username}",
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT'),
        request_path=request.path if hasattr(request, 'path') else None,
        request_method=request.method if hasattr(request, 'method') else None,
    )


@receiver(post_save)
def log_model_changes(sender, instance, created, **kwargs):
    """Log model create/update operations for sensitive models"""
    sensitive_models = [
        'User', 'APIKey', 'SecurityEvent', 'SecuritySettings'
    ]

    if sender.__name__ in sensitive_models:
        action = 'created' if created else 'updated'
        user = getattr(instance, 'user', None)

        # Skip logging for audit logs themselves to avoid recursion
        if sender.__name__ == 'AuditLog':
            return

        AuditLog.objects.create(
            user=user,
            event_type=AuditLog.EventType.DATA_MODIFICATION,
            severity=AuditLog.Severity.LOW,
            description=f"{sender.__name__} {action}: {instance}",
            additional_data={
                'model': sender.__name__,
                'action': action,
                'instance_id': str(instance.pk),  # Convert UUID to string
            }
        )


@receiver(post_delete)
def log_model_deletions(sender, instance, **kwargs):
    """Log model deletion operations for sensitive models"""
    sensitive_models = [
        'User', 'APIKey', 'SecurityEvent', 'SecuritySettings'
    ]

    if sender.__name__ in sensitive_models:
        user = getattr(instance, 'user', None)

        AuditLog.objects.create(
            user=user,
            event_type=AuditLog.EventType.DATA_MODIFICATION,
            severity=AuditLog.Severity.HIGH,
            description=f"{sender.__name__} deleted: {instance}",
            additional_data={
                'model': sender.__name__,
                'action': 'deleted',
                'instance_id': str(instance.pk),  # Convert UUID to string
            }
        )


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip