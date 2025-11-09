from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from .models import Notification
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def send_notification(self, notification_id):
    """Send notification via email"""
    try:
        notification = Notification.objects.get(id=notification_id)

        if notification.status != Notification.STATUS_PENDING:
            logger.warning(f"Notification {notification_id} is not pending, skipping")
            return
        site_name = settings.SITE_NAME or "Django"
        # Send email notification
        subject = notification.subject or f"{site_name} Notification"
        message = notification.body
        recipient_email = notification.recipient.email

        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient_email],
            fail_silently=False,
        )

        # Update notification status
        notification.status = Notification.STATUS_SENT
        notification.sent_at = timezone.now()
        notification.save()

        logger.info(f"Notification {notification_id} sent successfully to {recipient_email}")

    except Notification.DoesNotExist:
        logger.error(f"Notification {notification_id} does not exist")
    except Exception as exc:
        logger.error(f"Failed to send notification {notification_id}: {str(exc)}")
        # Retry the task
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))


@shared_task(bind=True, max_retries=3)
def send_bulk_notifications(self, notification_ids):
    """Send multiple notifications in bulk"""
    success_count = 0
    failure_count = 0

    for notification_id in notification_ids:
        try:
            send_notification.apply(args=[notification_id])
            success_count += 1
        except Exception as exc:
            logger.error(f"Failed to queue notification {notification_id}: {str(exc)}")
            failure_count += 1

    logger.info(f"Bulk notification send completed: {success_count} success, {failure_count} failures")
    return {"success": success_count, "failures": failure_count}


@shared_task
def cleanup_old_notifications():
    """Clean up old notifications based on retention policy"""
    from django.utils import timezone
    from datetime import timedelta

    # Delete notifications older than 90 days
    cutoff_date = timezone.now() - timedelta(days=90)
    deleted_count, _ = Notification.objects.filter(
        created_at__lt=cutoff_date,
        status__in=[Notification.STATUS_SENT, Notification.STATUS_DELIVERED]
    ).delete()

    logger.info(f"Cleaned up {deleted_count} old notifications")
    return deleted_count


@shared_task
def retry_failed_notifications():
    """Retry sending failed notifications"""
    failed_notifications = Notification.objects.filter(
        status=Notification.STATUS_FAILED
    ).order_by('created_at')[:50]  # Limit to 50 at a time

    retry_count = 0
    for notification in failed_notifications:
        try:
            send_notification.delay(str(notification.id))
            retry_count += 1
        except Exception as exc:
            logger.error(f"Failed to queue retry for notification {notification.id}: {str(exc)}")

    logger.info(f"Queued {retry_count} failed notifications for retry")
    return retry_count


@shared_task(bind=True, max_retries=3)
def send_scheduled_notifications(self):
    """Send notifications that are scheduled for now"""
    try:
        from django.utils import timezone
        
        # Find notifications scheduled for now or past
        scheduled_notifications = Notification.objects.filter(
            status=Notification.STATUS_PENDING,
            scheduled_at__lte=timezone.now()
        ).order_by('scheduled_at')[:50]  # Limit batch size

        sent_count = 0
        for notification in scheduled_notifications:
            try:
                send_notification.apply(args=[str(notification.id)])
                sent_count += 1
            except Exception as exc:
                logger.error(f"Failed to queue scheduled notification {notification.id}: {str(exc)}")

        logger.info(f"Queued {sent_count} scheduled notifications for sending")
        return sent_count

    except Exception as exc:
        logger.error(f"Failed to process scheduled notifications: {str(exc)}")
        raise self.retry(exc=exc, countdown=300)


@shared_task
def send_event_notifications(event_type: str, event_data: dict):
    """Send notifications for a specific event type"""
    try:
        from .models import NotificationEvent
        
        # Get the event configuration
        try:
            event_config = NotificationEvent.objects.get(event_type=event_type, is_active=True)
        except NotificationEvent.DoesNotExist:
            logger.warning(f"No active event configuration found for {event_type}")
            return 0

        # Determine recipients based on event_data
        recipients = get_event_recipients(event_type, event_data)
        
        sent_count = 0
        for recipient in recipients:
            try:
                # Create notification using appropriate template
                template = get_event_template(event_config, recipient)
                if template:
                    notification = Notification.objects.create(
                        recipient=recipient,
                        template=template,
                        data=event_data,
                        subject=template.subject,
                        body=template.body
                    )
                    send_notification.delay(str(notification.id))
                    sent_count += 1
            except Exception as exc:
                logger.error(f"Failed to create event notification for {recipient}: {str(exc)}")

        logger.info(f"Sent {sent_count} notifications for event {event_type}")
        return sent_count

    except Exception as exc:
        logger.error(f"Failed to send event notifications for {event_type}: {str(exc)}")
        raise


def get_event_recipients(event_type, event_data):
    """Determine recipients for an event"""
    # This would implement logic to determine who should receive notifications
    # based on the event type and data
    recipients = []
    
    if event_type == 'exam_created':
        # Notify relevant staff
        from django.contrib.auth import get_user_model
        User = get_user_model()
        recipients = User.objects.filter(is_staff=True)[:5]  # First 5 staff users
    
    elif 'moderation' in event_type:
        # Notify moderators and exam creators
        exam_id = event_data.get('exam_id')
        if exam_id:
            from apps.assessments.models import Assessment
            try:
                assessment = Assessment.objects.get(id=exam_id)
                recipients = [assessment.created_by]
                # Add assigned moderators if any
                # TODO: Update when moderation system is migrated to assessments
                # if hasattr(assessment, 'moderation_session') and assessment.moderation_session.assigned_moderator:
                #     recipients.append(assessment.moderation_session.assigned_moderator)
            except Assessment.DoesNotExist:
                pass
    
    return recipients


def get_event_template(event_config, recipient):
    """Get the appropriate template for an event and recipient"""
    # Check user preferences for notification type
    try:
        preferences = recipient.notification_preferences
        
        # Return appropriate template based on preferences
        if preferences.email_enabled and event_config.default_email_template:
            return event_config.default_email_template
        elif preferences.in_app_enabled and event_config.default_in_app_template:
            return event_config.default_in_app_template
        elif preferences.push_enabled and event_config.default_push_template:
            return event_config.default_push_template
        elif preferences.sms_enabled and event_config.default_sms_template:
            return event_config.default_sms_template
            
    except:
        # Fall back to email template
        return event_config.default_email_template
    
    return None


@shared_task
def generate_notification_analytics() -> dict:
    """Generate notification delivery analytics"""
    try:
        from django.utils import timezone
        from datetime import timedelta
        
        # Get stats for the last 24 hours
        since = timezone.now() - timedelta(hours=24)
        
        analytics = {
            'total_sent': Notification.objects.filter(sent_at__gte=since).count(),
            'total_delivered': Notification.objects.filter(delivered_at__gte=since).count(),
            'total_failed': Notification.objects.filter(
                status=Notification.STATUS_FAILED,
                created_at__gte=since
            ).count(),
            'delivery_rate': 0,
            'failure_rate': 0,
            'avg_delivery_time': calculate_avg_delivery_time(since),
            'top_event_types': get_top_event_types(since),
            'generated_at': str(timezone.now())
        }
        
        # Calculate rates
        total_sent = analytics['total_sent']
        if total_sent > 0:
            analytics['delivery_rate'] = (analytics['total_delivered'] / total_sent) * 100
            analytics['failure_rate'] = (analytics['total_failed'] / total_sent) * 100
        
        logger.info(f"Generated notification analytics: {analytics}")
        return analytics
        
    except Exception as exc:
        logger.error(f"Failed to generate notification analytics: {str(exc)}")
        raise


def calculate_avg_delivery_time(since):
    """Calculate average delivery time"""
    try:
        delivered_notifications = Notification.objects.filter(
            delivered_at__isnull=False,
            sent_at__isnull=False,
            sent_at__gte=since
        )
        
        if not delivered_notifications.exists():
            return 0
        
        total_time = sum(
            (n.delivered_at - n.sent_at).total_seconds()
            for n in delivered_notifications
        )
        
        return total_time / delivered_notifications.count()
        
    except Exception:
        return 0


def get_top_event_types(since):
    """Get top notification event types"""
    try:
        from django.db.models import Count
        
        top_events = Notification.objects.filter(
            created_at__gte=since
        ).values('template__name').annotate(
            count=Count('id')
        ).order_by('-count')[:5]
        
        return list(top_events)
        
    except Exception:
        return []


@shared_task(bind=True, max_retries=3)
def process_notification_queue(self):
    """Process pending notifications in queue"""
    try:
        pending_notifications = Notification.objects.filter(
            status=Notification.STATUS_PENDING,
            scheduled_at__isnull=True  # Not scheduled
        ).order_by('created_at')[:25]  # Process in batches
        
        processed_count = 0
        for notification in pending_notifications:
            try:
                send_notification.apply(args=[str(notification.id)])
                processed_count += 1
            except Exception as exc:
                logger.error(f"Failed to queue notification {notification.id}: {str(exc)}")
        
        logger.info(f"Processed {processed_count} notifications from queue")
        return processed_count
        
    except Exception as exc:
        logger.error(f"Failed to process notification queue: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)