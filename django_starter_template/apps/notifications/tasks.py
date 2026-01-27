from celery import shared_task
from django.conf import settings
from django.utils import timezone
from .models import Notification
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def send_notification(self, notification_id):
    """Send notification using NotificationService to ensure proper rendering and HTML delivery."""
    try:
        notification = Notification.objects.get(id=notification_id)

        if notification.status != Notification.STATUS_PENDING:
            logger.warning(f"Notification {notification_id} is not pending, skipping")
            return

        # If the notification is scheduled for the future, re-schedule this task
        # to run at the scheduled time instead of sending immediately. This
        # ensures callers that enqueue the task prematurely won't cause the
        # notification to be delivered before `scheduled_at`.
        if notification.scheduled_at:
            now = timezone.now()
            if notification.scheduled_at > now:
                logger.info(
                    f"Notification {notification_id} is scheduled for {notification.scheduled_at}, rescheduling task to run at that time"
                )
                try:
                    # Schedule the task to run at the notification.scheduled_at time
                    send_notification.apply_async(args=[str(notification.id)], eta=notification.scheduled_at)
                    return
                except Exception as exc:
                    logger.error(f"Failed to reschedule notification {notification_id}: {str(exc)}")
                    # Let the task retry if scheduling failed
                    raise self.retry(exc=exc, countdown=60)

        # Delegate delivery to the NotificationService which handles channels, rendering
        # and HTML/plain-text alternatives.
        from .services import NotificationService

        success = NotificationService.send_notification(notification)

        if success:
            logger.info(
                f"Notification {notification_id} sent successfully to {notification.recipient.email}"
            )
        else:
            # Let task retry if sending failed
            raise Exception("NotificationService failed to deliver notification")

    except Notification.DoesNotExist:
        logger.error(f"Notification {notification_id} does not exist")
    except Exception as exc:
        logger.error(f"Failed to send notification {notification_id}: {str(exc)}")
        # Retry the task
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))

@shared_task
def cleanup_old_notifications():
    """Clean up old notifications based on retention policy"""
    from django.utils import timezone
    from datetime import timedelta

    # Delete notifications older than 90 days
    cutoff_date = timezone.now() - timedelta(days=90)
    deleted_count, _ = Notification.objects.filter(
        created_at__lt=cutoff_date,
        status__in=[Notification.STATUS_SENT, Notification.STATUS_DELIVERED],
    ).delete()

    logger.info(f"Cleaned up {deleted_count} old notifications")
    return deleted_count


@shared_task
def retry_failed_notifications():
    """Retry sending failed notifications"""
    failed_notifications = Notification.objects.filter(
        status=Notification.STATUS_FAILED
    ).order_by("created_at")[
        :50
    ]  # Limit to 50 at a time

    retry_count = 0
    for notification in failed_notifications:
        try:
            # Respect any scheduled_at on the notification
            if notification.scheduled_at:
                now = timezone.now()
                if notification.scheduled_at > now:
                    send_notification.apply_async(args=[str(notification.id)], eta=notification.scheduled_at)
                else:
                    send_notification.delay(str(notification.id))
            else:
                send_notification.delay(str(notification.id))
            retry_count += 1
        except Exception as exc:
            logger.error(
                f"Failed to queue retry for notification {notification.id}: {str(exc)}"
            )

    logger.info(f"Queued {retry_count} failed notifications for retry")
    return retry_count


@shared_task(bind=True, max_retries=3)
def send_scheduled_notifications(self):
    """Send notifications that are scheduled for now"""
    try:
        from django.utils import timezone

        # Find notifications scheduled for now or past
        scheduled_notifications = Notification.objects.filter(
            status=Notification.STATUS_PENDING, scheduled_at__lte=timezone.now()
        ).order_by("scheduled_at")[
            :50
        ]  # Limit batch size

        sent_count = 0
        for notification in scheduled_notifications:
            try:
                # Enqueue the send task so workers will execute delivery
                send_notification.delay(str(notification.id))
                sent_count += 1
            except Exception as exc:
                logger.error(
                    f"Failed to queue scheduled notification {notification.id}: {str(exc)}"
                )

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
            event_config = NotificationEvent.objects.get(
                event_type=event_type, is_active=True
            )
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
                    # Use NotificationService to create the notification so the
                    # template is properly rendered (subject/body) and defaults
                    # like preferences are applied. This avoids storing raw HTML
                    # in the notification body which can cause plain-text parts
                    # to contain unrendered HTML.
                    from .services import NotificationService

                    notification = NotificationService.create_notification(
                        recipient=recipient,
                        template=template,
                        data=event_data or {},
                        priority=event_config.priority if hasattr(event_config, 'priority') else 'medium',
                    )
                    # Schedule send respecting notification.scheduled_at if present
                    if notification.scheduled_at:
                        if notification.scheduled_at > timezone.now():
                            send_notification.apply_async(args=[str(notification.id)], eta=notification.scheduled_at)
                        else:
                            send_notification.delay(str(notification.id))
                    else:
                        send_notification.delay(str(notification.id))
                    sent_count += 1
            except Exception as exc:
                logger.error(
                    f"Failed to create event notification for {recipient}: {str(exc)}"
                )

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
            "total_sent": Notification.objects.filter(sent_at__gte=since).count(),
            "total_delivered": Notification.objects.filter(
                delivered_at__gte=since
            ).count(),
            "total_failed": Notification.objects.filter(
                status=Notification.STATUS_FAILED, created_at__gte=since
            ).count(),
            "delivery_rate": 0,
            "failure_rate": 0,
            "avg_delivery_time": calculate_avg_delivery_time(since),
            "top_event_types": get_top_event_types(since),
            "generated_at": str(timezone.now()),
        }

        # Calculate rates
        total_sent = analytics["total_sent"]
        if total_sent > 0:
            analytics["delivery_rate"] = (
                analytics["total_delivered"] / total_sent
            ) * 100
            analytics["failure_rate"] = (analytics["total_failed"] / total_sent) * 100

        logger.info(f"Generated notification analytics: {analytics}")
        return analytics

    except Exception as exc:
        logger.error(f"Failed to generate notification analytics: {str(exc)}")
        raise


def calculate_avg_delivery_time(since):
    """Calculate average delivery time"""
    try:
        delivered_notifications = Notification.objects.filter(
            delivered_at__isnull=False, sent_at__isnull=False, sent_at__gte=since
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

        top_events = (
            Notification.objects.filter(created_at__gte=since)
            .values("template__name")
            .annotate(count=Count("id"))
            .order_by("-count")[:5]
        )

        return list(top_events)

    except Exception:
        return []


@shared_task(bind=True, max_retries=3)
def process_notification_queue(self):
    """Process pending notifications in queue"""
    try:
        pending_notifications = Notification.objects.filter(
            status=Notification.STATUS_PENDING,
            scheduled_at__isnull=True,  # Not scheduled
        ).order_by("created_at")[
            :25
        ]  # Process in batches

        processed_count = 0
        for notification in pending_notifications:
            try:
                # These notifications are not scheduled (scheduled_at__isnull=True)
                # so enqueue normally for immediate sending.
                send_notification.delay(str(notification.id))
                processed_count += 1
            except Exception as exc:
                logger.error(
                    f"Failed to queue notification {notification.id}: {str(exc)}"
                )

        logger.info(f"Processed {processed_count} notifications from queue")
        return processed_count

    except Exception as exc:
        logger.error(f"Failed to process notification queue: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)
