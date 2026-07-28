"""
Signals for the accounts app.

Note for anyone comparing against the template: this module used to be **two
complete modules concatenated** — a second module docstring, a second set of
imports, and a second `logger = ...` / `User = ...` began partway down the
file. Both halves registered `post_save` handlers on `User`, so every user
creation ran two different "send the welcome message" paths.

The first half was removed. It duplicated the welcome notification, and its
only unique behaviour — an `account_activated` notification on is_active
False->True, and a `role_changed` notification on a groups m2m change — routed
through `apps.notifications`, which is disabled (see
settingsConfig/core/apps.py). Those two events are worth having; they should be
re-implemented as explicit service calls in a reworked notifications app
rather than as signals.
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
        # apps.notifications is not installed by default (see
        # settingsConfig/core/apps.py for why). Without this guard every user
        # creation logged an ERROR with a "no such table" traceback — noise
        # that trains people to ignore ERROR lines, which is how a real failure
        # gets missed. Depending on an optional app is the app's job to check.
        from django.apps import apps as django_apps

        if not django_apps.is_installed("apps.notifications"):
            logger.debug(
                "Skipping welcome notification for %s: apps.notifications is not installed.",
                instance.email,
            )
            return

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
                    "platform_name": getattr(settings, 'PLATFORM_NAME', 'Your Platform'),
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
