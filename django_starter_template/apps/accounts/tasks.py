"""
Celery tasks for the accounts app
"""
from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def send_welcome_email(self, user_id):
    """Send welcome email to new user"""
    try:
        user = User.objects.get(id=user_id)

        subject = "Welcome!"
        message = f"""
        Welcome {user.first_name or 'User'}!

        Your account has been successfully created. You can now log in and access the system.

        If you have any questions, please contact support.

        Best regards,
        The Team
        """

        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )

        logger.info(f"Welcome email sent to user: {user.email}")

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

        reset_url = f"{settings.FRONTEND_URL}/reset-password/{reset_token}"

        subject = "Password Reset Request"
        message = f"""
        Hello {user.first_name or 'User'},

        You have requested to reset your password. Click the link below to reset it:

        {reset_url}

        This link will expire in 24 hours.

        If you didn't request this password reset, please ignore this email.

        Best regards,
        The Team
        """

        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )

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
        is_staff=False  # Don't deactivate staff
    )

    deactivated_count = 0
    for user in inactive_users:
        user.is_active = False
        user.save()
        deactivated_count += 1

        logger.info(f"Deactivated inactive user: {user.email}")

    logger.info(f"Deactivated {deactivated_count} inactive users")
    return deactivated_count


@shared_task(bind=True, max_retries=3)
def send_account_notification(self, user_id, notification_type, custom_message=None):
    """Send account-related notification to user"""
    try:
        user = User.objects.get(id=user_id)

        if notification_type == 'account_activated':
            subject = "Account Activated"
            message = "Your account has been activated. You can now log in and access all features."
        elif notification_type == 'account_deactivated':
            subject = "Account Deactivated"
            message = "Your account has been deactivated. Please contact support if you have questions."
        elif notification_type == 'password_changed':
            subject = "Password Changed"
            message = "Your password has been successfully changed."
        elif notification_type == 'profile_updated':
            subject = "Profile Updated"
            message = "Your profile has been successfully updated."
        else:
            subject = "Account Notification"
            message = custom_message or "You have a new account notification."

        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )

        logger.info(f"Account notification sent to user: {user.email}")

    except User.DoesNotExist:
        logger.error(f"User {user_id} does not exist")
    except Exception as exc:
        logger.error(f"Failed to send account notification to user {user_id}: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)