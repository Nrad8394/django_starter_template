"""
Celery tasks for the accounts app
"""

from celery import shared_task
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
import logging
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator

User = get_user_model()
logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def send_welcome_email(self, user_id):
    """Send comprehensive welcome email to new user with password setup link"""
    try:
        user = User.objects.get(id=user_id)

        # Generate password setup/reset token and UID
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = f"{getattr(settings, 'FRONTEND_URL', '')}/auth/set-password/{uid}/{token}"

        # Get role information
        role = user.role
        role_name = role.display_name if role else "User"
        role_descriptions = {
            "Admin": "As Administrator, you have full system access including user management, settings, and institution analytics.",
        }
        role_description = role_descriptions.get(role_name, f"You have been assigned the {role_name} role.")

        context = {
            "user_name": user.get_full_name() or user.email,
            "user_id": str(user.id),
            "email": user.email,
            "role": role_name,
            "role_description": role_description,
            "reset_link": reset_link,
            "expiry_hours": 24,
            "platform_name": getattr(settings, "PLATFORM_NAME", "NNP Logx"),
            "support_email": getattr(settings, "SUPPORT_EMAIL", "support@nnplogx.com"),
            "frontend_url": getattr(settings, "FRONTEND_URL", ""),
        }

        html_message = render_to_string("emails/welcome_complete.html", context)
        text_message = strip_tags(html_message)

        subject = f"Welcome to {getattr(settings, 'PLATFORM_NAME', 'NNP Logx')} - Account Setup Required"

        # Create email with plain-text primary and HTML alternative (multipart/alternative)
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.attach_alternative(html_message, "text/html")

        # Add header to help trace email source
        try:
            email.extra_headers = {"X-Email-Source": "accounts.send_welcome_email"}
        except Exception:
            pass

        email.send(fail_silently=False)

        logger.info(f"Comprehensive welcome email sent to user: {user.email} (Role: {role_name})")

    except User.DoesNotExist:
        logger.error(f"User {user_id} does not exist")
    except Exception as exc:
        logger.error(f"Failed to send welcome email to user {user_id}: {str(exc)}")
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))


@shared_task(bind=True, max_retries=3)
def send_password_reset_email(self, user_id, reset_token):
    """Send password reset email"""
    try:
        user = User.objects.get(id=user_id)

        reset_url = f"{settings.FRONTEND_URL}/auth/reset-password/{reset_token}"

        subject = "Password Reset Request"
        html_message = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #1e3c72; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 30px; background: #f9f9f9; }}
                .button {{ display: inline-block; padding: 12px 24px; background: #dc2626; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .footer {{ font-size: 12px; color: #666; text-align: center; padding: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>Password Reset Request</h2>
                </div>
                <div class="content">
                    <h3>Hello {user.first_name or 'User'},</h3>
                    <p>You have requested to reset your password for your {{ platform_name }} account.</p>
                    <p>Click the button below to reset your password:</p>
                    <div style="text-align: center;">
                        <a href="{reset_url}" class="button">Reset Password</a>
                    </div>
                    <p><strong>This link will expire in 24 hours.</strong></p>
                    <p>If you didn't request this password reset, please ignore this email. Your password will remain unchanged.</p>
                    <p>For security reasons, please do not share this email with anyone.</p>
                </div>
                <div class="footer">
                    <p>This is an automated message. Please do not reply to this email.</p>
                    <p>If you need help, contact support at {getattr(settings, 'SUPPORT_EMAIL', 'support@nnplogx.com')}</p>
                </div>
            </div>
        </body>
        </html>
        """
        text_message = f"""
        Hello {user.first_name or 'User'},

        You have requested to reset your password for your {{ platform_name }} account.

        Click the link below to reset your password:
        {reset_url}

        This link will expire in 24 hours.

        If you didn't request this password reset, please ignore this email. Your password will remain unchanged.

        For security reasons, please do not share this email with anyone.

        Best regards,
        The {{ platform_name }} Team
        """

        email = EmailMultiAlternatives(
            subject=subject,
            body=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.attach_alternative(html_message, "text/html")
        # Add header to help trace email source
        try:
            email.extra_headers = {"X-Email-Source": "accounts.send_password_reset_email"}
        except Exception:
            pass
        email.send(fail_silently=False)

        logger.info(f"Password reset email sent to user: {user.email}")

    except User.DoesNotExist:
        logger.error(f"User {user_id} does not exist")
    except Exception as exc:
        logger.error(f"Failed to send password reset email to user {user_id}: {str(exc)}")
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))


@shared_task
def deactivate_inactive_users():
    """Deactivate users who haven't logged in for extended period"""
    cutoff_date = timezone.now() - timezone.timedelta(days=365)  # 1 year

    inactive_users = User.objects.filter(
        last_login__lt=cutoff_date,
        is_active=True,
        is_staff=False,  # Don't deactivate staff
    )

    deactivated_count = 0
    for user in inactive_users:
        user.is_active = False
        user.save()
        deactivated_count += 1

        logger.info(f"Deactivated inactive user: {user.email}")

    logger.info(f"Deactivated {deactivated_count} inactive users")
    return deactivated_count





@shared_task
def cleanup_expired_sessions():
    """Clean up expired user sessions"""
    from .models import UserSession

    now = timezone.now()

    # Mark expired sessions as inactive
    expired_sessions = UserSession.objects.filter(is_active=True, expires_at__lt=now)

    expired_count = expired_sessions.update(is_active=False)

    # Delete old inactive sessions (older than 30 days)
    old_sessions_cutoff = now - timezone.timedelta(days=30)
    deleted_count = UserSession.objects.filter(
        is_active=False, updated_at__lt=old_sessions_cutoff
    ).delete()[0]

    logger.info(
        f"Cleaned up {expired_count} expired sessions and deleted {deleted_count} old sessions"
    )
    return expired_count, deleted_count


@shared_task
def cleanup_expired_rate_limits():
    """Clean up expired rate limit records"""
    from apps.security.models import RateLimit

    now = timezone.now()

    # Remove old rate limit records that are no longer blocked
    old_records = RateLimit.objects.filter(
        is_blocked=False, window_end__lt=now - timezone.timedelta(hours=24)
    )

    deleted_count = old_records.delete()[0]

    # Unblock expired blocks
    expired_blocks = RateLimit.objects.filter(is_blocked=True, blocked_until__lt=now)

    unblocked_count = expired_blocks.update(is_blocked=False, blocked_until=None)

    logger.info(
        f"Cleaned up {deleted_count} old rate limit records and unblocked {unblocked_count} expired blocks"
    )
    return deleted_count, unblocked_count