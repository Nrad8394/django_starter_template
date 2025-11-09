from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import Notification, NotificationTemplate, NotificationPreference, NotificationEvent, NotificationDelivery
import logging

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Notification)
def handle_notification_creation(sender, instance, created, **kwargs):
    """Handle notification creation and trigger sending"""
    if created and instance.status == Notification.STATUS_PENDING:
        logger.info(f"New notification created: {instance.id} for {instance.recipient}")

        # Schedule notification for sending
        try:
            from .tasks import send_notification
            send_notification.delay(str(instance.id))
        except Exception as e:
            logger.error(f"Failed to schedule notification {instance.id}: {str(e)}")


@receiver(pre_save, sender=Notification)
def track_status_changes(sender, instance, **kwargs):
    """Track notification status changes for analytics"""
    if instance.pk:
        try:
            old_instance = Notification.objects.get(pk=instance.pk)
            if old_instance.status != instance.status:
                logger.info(f"Notification {instance.id} status changed: {old_instance.status} -> {instance.status}")

                # Update timestamps based on status
                if instance.status == Notification.STATUS_SENT and not instance.sent_at:
                    instance.sent_at = timezone.now()
                elif instance.status == Notification.STATUS_DELIVERED and not instance.delivered_at:
                    instance.delivered_at = timezone.now()

        except Notification.DoesNotExist:
            pass


@receiver(post_save, sender=NotificationTemplate)
def validate_template_variables(sender, instance, created, **kwargs):
    """Validate template variables when template is saved"""
    if created or instance.body:
        # Could add template variable validation here
        logger.info(f"Notification template {instance.name} saved")


@receiver(post_save, sender=Notification)
def track_delivery_metrics(sender, instance, created, **kwargs):
    """Track delivery metrics for notifications"""
    if not created:
        logger.info(f"Tracking delivery metrics for notification {instance.id}")
        
        try:
            # Update delivery statistics
            if instance.status == Notification.STATUS_DELIVERED:
                logger.info(f"Notification {instance.id} delivered successfully")
            elif instance.status == Notification.STATUS_FAILED:
                logger.warning(f"Notification {instance.id} delivery failed: {instance.last_error}")
                
                # Could trigger retry logic or escalation
                if instance.retry_count < instance.max_retries:
                    from .tasks import retry_failed_notifications
                    retry_failed_notifications.delay()
                    
        except Exception as exc:
            logger.error(f"Failed to track delivery metrics: {str(exc)}")


@receiver(post_save, sender=NotificationPreference)
def validate_preference_consistency(sender, instance, created, **kwargs):
    """Validate notification preference consistency"""
    if not created:
        logger.info(f"Validating preferences for user {instance.user.id}")
        
        try:
            # Ensure at least one channel is enabled
            channels_enabled = (
                instance.email_enabled or 
                instance.sms_enabled or 
                instance.push_enabled or 
                instance.in_app_enabled
            )
            
            if not channels_enabled:
                logger.warning(f"User {instance.user} has no notification channels enabled")
                
                # Could send warning or enable default channel
                instance.in_app_enabled = True  # Enable in-app as fallback
                instance.save(update_fields=['in_app_enabled'])
                
        except Exception as exc:
            logger.error(f"Failed to validate preference consistency: {str(exc)}")


@receiver(post_save, sender=NotificationEvent)
def update_event_templates(sender, instance, created, **kwargs):
    """Update event templates when event configuration changes"""
    if not created:
        logger.info(f"Updating templates for event {instance.event_type}")
        
        try:
            # Validate that templates exist and are active
            templates_to_check = [
                instance.default_email_template,
                instance.default_sms_template,
                instance.default_push_template,
                instance.default_in_app_template
            ]
            
            for template in templates_to_check:
                if template and not template.is_active:
                    logger.warning(f"Event {instance.event_type} references inactive template {template.name}")
                    
                    # Could disable the event or update the template reference
                    # For now, just log the issue
                    
        except Exception as exc:
            logger.error(f"Failed to update event templates: {str(exc)}")


@receiver(post_save, sender=Notification)
def enforce_quiet_hours(sender, instance, created, **kwargs):
    """Enforce quiet hours for notifications"""
    if created:
        logger.info(f"Enforcing quiet hours for notification {instance.id}")
        
        try:
            preferences = instance.recipient.notification_preferences
            
            if preferences.quiet_hours_start and preferences.quiet_hours_end:
                from django.utils import timezone
                
                now = timezone.now().time()
                start = preferences.quiet_hours_start
                end = preferences.quiet_hours_end
                
                # Check if current time is within quiet hours
                if start <= end:
                    # Same day range
                    in_quiet_hours = start <= now <= end
                else:
                    # Overnight range
                    in_quiet_hours = now >= start or now <= end
                
                if in_quiet_hours and instance.priority not in ['urgent', 'high']:
                    logger.info(f"Delaying notification {instance.id} due to quiet hours")
                    
                    # Delay until end of quiet hours
                    from datetime import datetime, time
                    tomorrow = timezone.now().date()
                    if now <= end:
                        delay_until = timezone.make_aware(
                            datetime.combine(tomorrow, end)
                        )
                    else:
                        delay_until = timezone.make_aware(
                            datetime.combine(tomorrow, end)
                        )
                    
                    instance.scheduled_at = delay_until
                    instance.save(update_fields=['scheduled_at'])
                    
        except Exception as exc:
            logger.error(f"Failed to enforce quiet hours: {str(exc)}")


@receiver(post_save, sender=NotificationDelivery)
def track_delivery_provider_metrics(sender, instance, created, **kwargs):
    """Track delivery provider metrics"""
    if created:
        logger.info(f"Tracking provider metrics for delivery {instance.id}")
        
        try:
            # Update provider success/failure rates
            if instance.status == 'delivered':
                logger.info(f"Successful delivery via {instance.provider}")
            elif instance.status == 'failed':
                logger.warning(f"Failed delivery via {instance.provider}: {instance.error_message}")
                
                # Could update provider reliability metrics
                # For now, just log
                
        except Exception as exc:
            logger.error(f"Failed to track provider metrics: {str(exc)}")


@receiver(post_save, sender=Notification)
def trigger_notification_events(sender, instance, created, **kwargs):
    """Trigger events based on notification lifecycle"""
    if not created:
        logger.info(f"Triggering events for notification {instance.id}")
        
        try:
            from apps.workflow.tasks import trigger_workflow_from_event
            
            event_data = {
                'notification_id': instance.id,
                'recipient_id': instance.recipient.id,
                'template_name': instance.template.name,
                'status': instance.status,
                'priority': instance.priority
            }
            
            if instance.status == Notification.STATUS_DELIVERED:
                trigger_workflow_from_event.delay('notification_delivered', event_data)
            elif instance.status == Notification.STATUS_FAILED:
                trigger_workflow_from_event.delay('notification_failed', event_data)
                
        except Exception as exc:
            logger.error(f"Failed to trigger notification events: {str(exc)}")


@receiver(post_save, sender=NotificationTemplate)
def validate_template_content(sender, instance, created, **kwargs):
    """Validate template content and variables"""
    if not created:
        logger.info(f"Validating content for template {instance.name}")
        
        try:
            # Check for required variables in template body
            import re
            
            # Find all {{variable}} patterns
            variables_in_template = set(re.findall(r'\{\{(\w+)\}\}', instance.body))
            
            # Check against defined variables schema
            defined_variables = set(instance.variables.keys()) if instance.variables else set()
            
            undefined_vars = variables_in_template - defined_variables
            if undefined_vars:
                logger.warning(f"Template {instance.name} uses undefined variables: {undefined_vars}")
                
                # Could add the variables to schema or flag for review
                
        except Exception as exc:
            logger.error(f"Failed to validate template content: {str(exc)}")


@receiver(post_save, sender=Notification)
def update_user_notification_stats(sender, instance, created, **kwargs):
    """Update user notification statistics"""
    if not created:
        logger.info(f"Updating stats for user {instance.recipient.id}")
        
        try:
            # Could update user notification preferences based on engagement
            # For example, if user never opens emails, suggest disabling email notifications
            
            preferences = instance.recipient.notification_preferences
            
            # Simple example: track notification volume
            # In a real implementation, you'd have a stats model
            
            logger.info(f"User {instance.recipient} notification stats updated")
            
        except Exception as exc:
            logger.error(f"Failed to update user notification stats: {str(exc)}")


# Import here to avoid circular imports
def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip