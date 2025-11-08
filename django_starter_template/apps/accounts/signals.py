"""
Signals for the accounts app
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User, UserProfile


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Signal handler to create a UserProfile when a User is created.
    """
    if created:
        UserProfile.objects.create(
            user=instance,
            bio=f"Profile for {instance.get_full_name() or instance.email}",
            preferred_language='en',
            allow_notifications=True
        )


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Signal handler to save the UserProfile when a User is saved.
    """
    if hasattr(instance, 'profile'):
        instance.profile.save()