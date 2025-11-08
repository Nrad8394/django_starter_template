from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.admin.models import ADDITION, CHANGE, DELETION
from django.contrib.contenttypes.models import ContentType
from django.contrib.admin.models import LogEntry
# Note To make this work, you need to attach the request.user to the model
#  instance before saving. One common pattern is overriding
# perform_create / perform_update in your DRF views and setting:
# serializer.save(_current_user=self.request.user)
@receiver(post_save)
def log_save(sender, instance, created, **kwargs):
    if sender._meta.app_label in ["auth", "admin"]:  # skip system models
        return
    user = getattr(instance, "_current_user", None)
    if user:
        LogEntry.objects.log_action(
            user_id=user.pk,
            content_type_id=ContentType.objects.get_for_model(instance).pk,
            object_id=instance.pk,
            object_repr=str(instance),
            action_flag=ADDITION if created else CHANGE,
            change_message="Saved via API",
        )

@receiver(post_delete)
def log_delete(sender, instance, **kwargs):
    user = getattr(instance, "_current_user", None)
    if user:
        LogEntry.objects.log_action(
            user_id=user.pk,
            content_type_id=ContentType.objects.get_for_model(instance).pk,
            object_id=instance.pk,
            object_repr=str(instance),
            action_flag=DELETION,
            change_message="Deleted via API",
        )