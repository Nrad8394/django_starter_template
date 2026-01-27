import logging
from typing import Optional

from django.contrib.auth import get_user_model
from django.db.models.signals import post_save, pre_save, m2m_changed
from django.dispatch import receiver

from apps.notifications.services import NotificationService

logger = logging.getLogger(__name__)
User = get_user_model()


@receiver(pre_save, sender=User)
def _capture_previous_user_state(sender, instance: User, **kwargs):
    """Capture previous values on the instance so post_save can detect changes.

    We attach a transient attribute _previous_is_active used by post_save.
    """
    try:
        if not instance.pk:
            # New user; default previous state is inactive unless provided
            instance._previous_is_active = False
            return

        prev = sender.objects.filter(pk=instance.pk).values("is_active").first()
        instance._previous_is_active = bool(prev and prev.get("is_active"))
    except Exception as e:
        logger.exception("Failed to capture previous user state: %s", e)
        instance._previous_is_active = False


@receiver(post_save, sender=User)
def user_post_save_send_account_notifications(sender, instance: User, created: bool, **kwargs):
    """Send account-related notifications on user create and activation.

    - On create => 'welcome'
    - On activation (is_active changed False->True) => 'account_activated'
    """
    try:
        # Welcome on creation
        if created:
            try:
                NotificationService.send_account_notification(
                    recipient=instance, notification_type="welcome"
                )
            except Exception:
                logger.exception("Failed to send welcome notification for user %s", instance)

        # Activation change detection
        previous_active = getattr(instance, "_previous_is_active", False)
        current_active = bool(getattr(instance, "is_active", False))
        if not created and (not previous_active) and current_active:
            try:
                NotificationService.send_account_notification(
                    recipient=instance, notification_type="account_activated"
                )
            except Exception:
                logger.exception("Failed to send account_activated notification for user %s", instance)

    except Exception as e:
        logger.exception("Error in user_post_save_send_account_notifications: %s", e)


@receiver(m2m_changed, sender=User.groups.through)
def user_groups_changed_send_role_change(sender, instance: User, action: str, **kwargs):
    """Notify user when their groups/roles change.

    We treat any post_add/post_remove/post_clear as a role change.
    """
    try:
        if action in ("post_add", "post_remove", "post_clear"):
            try:
                NotificationService.send_account_notification(
                    recipient=instance, notification_type="role_changed"
                )
            except Exception:
                logger.exception("Failed to send role_changed notification for user %s", instance)
    except Exception:
        logger.exception("Error handling user groups m2m_changed signal for user %s", instance)
"""
Signals for the accounts app
"""

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.conf import settings
import logging

from .models import User, UserProfile

logger = logging.getLogger(__name__)


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Signal handler to create a UserProfile when a User is created.
    Uses get_or_create to be idempotent (prevent duplicates).
    """
    if created:
        UserProfile.objects.get_or_create(
            user=instance,
            defaults={
                "bio": f"Profile for {instance.get_full_name() or instance.email}",
                "preferred_language": "en",
                "allow_notifications": True,
            }
        )


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Signal handler to save the UserProfile when a User is saved.
    """
    if hasattr(instance, "profile"):
        instance.profile.save()


@receiver(post_save, sender=User)
def send_user_creation_notification(sender, instance, created, **kwargs):
    """
    Send a single, comprehensive welcome email with account details and password reset link.
    This consolidates all user creation notifications into one well-formatted email.
    
    This signal:
    1. Fires only on user creation (not update)
    2. Generates a secure password reset token (24 hour expiry)
    3. Retrieves the consolidated "User Welcome Complete" template
    4. Sends the email via NotificationService
    5. Gracefully handles errors without failing user creation
    """
    if created:
        try:
            # Import here to avoid circular imports
            from apps.notifications.models import NotificationTemplate
            from apps.notifications.services import NotificationService
            
            # Mark user as needing password change (only if password not set)
            if not instance.password or instance.password == '!':
                User.objects.filter(pk=instance.pk).update(must_change_password=True)
            
            # Generate password reset token and uid
            token = default_token_generator.make_token(instance)
            uid = urlsafe_base64_encode(force_bytes(instance.pk))
            
            # Construct reset link - matches frontend route
            frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')
            reset_link = f"{frontend_url}/auth/set-password/{uid}/{token}/"
            
            try:
                # Get the consolidated welcome template
                welcome_template = NotificationTemplate.objects.get(
                    name="User Welcome Complete",
                    is_active=True
                )
                
                # Prepare comprehensive data for the email template
                # These variables should match the template variables defined in migration
                data = {
                    "user_name": instance.get_full_name() or instance.email,
                    "user_id": str(instance.id),
                    "email": instance.email,
                    "role": instance.role.display_name if instance.role else "No role assigned",
                    "role_description": instance.role.description if instance.role else "Your role will be assigned by an administrator.",
                    "reset_link": reset_link,
                    "expiry_hours": 24,
                    "support_email": getattr(settings, 'SUPPORT_EMAIL', 'support@example.com'),
                    "platform_name": getattr(settings, 'PLATFORM_NAME', 'Smart School Management'),
                }
                
                # Create notification instance (status will be pending)
                NotificationService.create_notification(
                    recipient=instance,
                    template=welcome_template,
                    data=data,
                    priority="high",
                )
                
                logger.info(
                    f"Created welcome notification for user {instance.email} "
                    f"(Role: {data['role']}) - will be sent asynchronously"
                )
                
            except NotificationTemplate.DoesNotExist:
                # Graceful fallback: Log warning but don't fail user creation
                logger.warning(
                    f"Welcome template 'User Welcome Complete' not found for user {instance.email}. "
                    f"Please ensure the template exists by running: "
                    f"python manage.py migrate notifications"
                )
                # Could optionally send email directly here as fallback
                
        except Exception as e:
            # Critical: Don't fail user creation if notifications fail
            # This ensures user is created even if email system is down
            logger.error(
                f"Failed to send welcome notification to user {instance.email}: {str(e)}"
            )


@receiver(post_save, sender=User)
def handle_profile_image_upload(sender, instance, created, update_fields, **kwargs):
    """
    Signal handler to mark profile as complete when profile_image is uploaded.
    Automatically sets profile_complete and profile_completed_at timestamps.
    """
    from django.utils import timezone
    
    # Only process if profile_image was updated
    if update_fields and 'profile_image' not in update_fields:
        return
    
    # If profile_image is set and profile is not yet marked complete
    if instance.profile_image and not instance.profile_complete:
        try:
            User.objects.filter(pk=instance.pk).update(
                profile_complete=True,
                profile_completed_at=timezone.now()
            )
            logger.info(f"Marked profile as complete for user {instance.id} due to profile image upload")
        except Exception as e:
            logger.error(f"Error marking profile complete for user {instance.id}: {str(e)}")
