import logging
from typing import Dict, List, Optional
from django.template import Template, Context
from django.utils import timezone
from django.contrib.auth import get_user_model
from .models import (
    NotificationTemplate,
    Notification,
    NotificationDelivery,
    NotificationPreference,
    NotificationEvent,
)

logger = logging.getLogger(__name__)
User = get_user_model()


class NotificationService:
    """Service for handling notification operations"""

    @staticmethod
    def render_template(template: NotificationTemplate, data: Dict) -> Dict[str, str]:
        """Render template with provided data"""
        try:
            context = Context(data)
            rendered = {
                "subject": (
                    Template(template.subject or "").render(context)
                    if template.subject
                    else ""
                ),
                "body": Template(template.body).render(context),
            }
            return rendered
        except Exception as e:
            logger.error(f"Template rendering error: {e}")
            return {"subject": template.subject or "", "body": template.body}

    @staticmethod
    def create_notification(
        recipient: User,
        template: NotificationTemplate,
        data: Optional[Dict] = None,
        scheduled_at: Optional[timezone.datetime] = None,
        priority: str = "medium",
    ) -> Notification:
        """Create a notification instance"""
        data = data or {}

        # Render template
        rendered = NotificationService.render_template(template, data)

        # Create notification
        notification = Notification.objects.create(
            recipient=recipient,
            template=template,
            subject=rendered["subject"],
            body=rendered["body"],
            data=data,
            scheduled_at=scheduled_at,
            priority=priority,
        )

        logger.info(
            f"Created notification {notification.id} for user {recipient.get_username()}"
        )
        return notification

    @staticmethod
    def send_notification(notification: Notification) -> bool: 
        """Send a notification through appropriate channels"""
        try:
            # Check user preferences
            preferences = NotificationPreference.objects.filter(
                user=notification.recipient
            ).first()
            if not preferences:
                # Create default preferences
                preferences = NotificationPreference.objects.create(
                    user=notification.recipient,
                    email_enabled=True,
                    sms_enabled=False,
                    push_enabled=True,
                    in_app_enabled=True,
                )

            # Determine delivery channels based on template type and user preferences
            channels = NotificationService._get_delivery_channels(
                notification.template.template_type, preferences
            )

            success = False
            for channel in channels:
                delivery = NotificationDelivery.objects.create(
                    notification=notification,
                    delivery_method=channel,
                    recipient_address=NotificationService._get_recipient_address(
                        notification.recipient, channel, preferences
                    ),
                )

                # Attempt delivery
                if NotificationService._deliver_to_channel(delivery):
                    success = True
                    delivery.status = NotificationDelivery.STATUS_DELIVERED
                    delivery.delivered_at = timezone.now()
                else:
                    delivery.status = NotificationDelivery.STATUS_FAILED
                    delivery.error_message = "Delivery failed"

                delivery.save()

            # Update notification status
            if success:
                notification.status = Notification.STATUS_DELIVERED
                notification.delivered_at = timezone.now()
            else:
                notification.status = Notification.STATUS_FAILED
                notification.last_error = "All delivery channels failed"

            notification.sent_at = timezone.now()
            notification.save()

            return success

        except Exception as e:
            logger.error(f"Failed to send notification {notification.id}: {e}")
            notification.status = Notification.STATUS_FAILED
            notification.last_error = str(e)
            notification.save()
            return False

    @staticmethod
    def _get_delivery_channels(
        template_type: str, preferences: NotificationPreference
    ) -> List[str]:
        """Determine which channels to use based on template type and preferences"""
        channels = []

        if (
            template_type == NotificationTemplate.TYPE_EMAIL
            and preferences.email_enabled
        ):
            channels.append(NotificationDelivery.DELIVERY_EMAIL)
        elif template_type == NotificationTemplate.TYPE_SMS and preferences.sms_enabled:
            channels.append(NotificationDelivery.DELIVERY_SMS)
        elif (
            template_type == NotificationTemplate.TYPE_PUSH and preferences.push_enabled
        ):
            channels.append(NotificationDelivery.DELIVERY_PUSH)
        elif (
            template_type == NotificationTemplate.TYPE_IN_APP
            and preferences.in_app_enabled
        ):
            channels.append(NotificationDelivery.DELIVERY_IN_APP)

        return channels

    @staticmethod
    def _get_recipient_address(
        user: User, channel: str, preferences: NotificationPreference
    ) -> str:
        """Get the recipient address for a delivery channel"""
        if channel == NotificationDelivery.DELIVERY_EMAIL:
            return preferences.email_address or user.email
        elif channel == NotificationDelivery.DELIVERY_SMS:
            return preferences.phone_number or ""
        elif channel == NotificationDelivery.DELIVERY_PUSH:
            # Return device tokens as JSON string
            return str(preferences.device_tokens)
        elif channel == NotificationDelivery.DELIVERY_IN_APP:
            return str(user.id)
        return ""

    @staticmethod
    def _deliver_to_channel(delivery: NotificationDelivery) -> bool:
        """Deliver notification to a specific channel"""
        try:
            if delivery.delivery_method == NotificationDelivery.DELIVERY_EMAIL:
                return NotificationService._send_email(delivery)
            elif delivery.delivery_method == NotificationDelivery.DELIVERY_SMS:
                return NotificationService._send_sms(delivery)
            elif delivery.delivery_method == NotificationDelivery.DELIVERY_PUSH:
                return NotificationService._send_push(delivery)
            elif delivery.delivery_method == NotificationDelivery.DELIVERY_IN_APP:
                return NotificationService._send_in_app(delivery)
            return False
        except Exception as e:
            logger.error(f"Channel delivery failed: {e}")
            return False

    @staticmethod
    def _send_email(delivery: NotificationDelivery) -> bool:
        """Send email notification using HTML templates"""
        from django.core.mail import EmailMultiAlternatives
        from django.template.loader import render_to_string
        from django.conf import settings
        from django.utils.html import strip_tags
        import re
        
        try:
            # Prepare context for email template
            context = {
                'subject': delivery.notification.subject,
                'body': delivery.notification.body,
                'notification': delivery.notification,
                'recipient': delivery.notification.recipient,
                'data': delivery.notification.data,
            }
            
            # Render HTML content
            html_content = render_to_string(
                'emails/notification_base.html',
                context
            )

            # Remove <style> blocks so CSS doesn't appear in the plain-text fallback
            cleaned_html = re.sub(r'(?is)<style.*?>.*?</style>', '', html_content)

            # Create plain text version (fallback)
            text_content = strip_tags(cleaned_html)

            # Compose proper From header (display name + address)
            from_address = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@example.com")
            display_name = getattr(settings, "PLATFORM_NAME", "Smart School Management")
            display_from = f"{display_name} <{from_address}>"

            # Use support email as Reply-To so replies go to support, fallback to from_address
            reply_to_address = getattr(settings, "SUPPORT_EMAIL", from_address)

            # Create email message with plain-text as primary body and HTML attached as alternative
            email = EmailMultiAlternatives(
                subject=delivery.notification.subject,
                body=text_content,
                from_email=display_from,
                to=[delivery.recipient_address],
                reply_to=[reply_to_address],
            )

            # Attach HTML alternative
            email.attach_alternative(html_content, "text/html")
            # Add a header to help trace emails coming from the notification service
            # Add tracing header; keep existing headers intact when possible
            try:
                headers = email.extra_headers or {}
                headers.update({"X-Email-Source": "notifications.NotificationService"})
                email.extra_headers = headers
            except Exception:
                pass
            
            # Send email
            email.send(fail_silently=False)
            
            logger.info(
                f"Sent email to {delivery.recipient_address}: {delivery.notification.subject}"
            )
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {delivery.recipient_address}: {e}")
            return False

    @staticmethod
    def _send_sms(delivery: NotificationDelivery) -> bool:
        """Send SMS notification"""
        # Placeholder for SMS sending logic
        # In production, integrate with Twilio, AWS SNS, etc.
        logger.info(
            f"Sending SMS to {delivery.recipient_address}: {delivery.notification.body[:50]}..."
        )
        return True  # Simulate success

    @staticmethod
    def _send_push(delivery: NotificationDelivery) -> bool:
        """Send push notification"""
        # Placeholder for push notification logic
        # In production, integrate with FCM, APNS, etc.
        logger.info(
            f"Sending push notification to devices: {delivery.recipient_address}"
        )
        return True  # Simulate success

    @staticmethod
    def _send_in_app(delivery: NotificationDelivery) -> bool:
        """Send in-app notification"""
        # For in-app notifications, we just mark as delivered
        # The frontend will handle displaying the notification
        logger.info(
            f"In-app notification created for user {delivery.notification.recipient.get_username()}"
        )
        return True

    @staticmethod
    def trigger_event_notification(
        event_type: str,
        recipient: User,
        data: Optional[Dict] = None,
        priority: str = "medium",
    ) -> Optional[Notification]:
        """Trigger a notification based on a system event"""
        try:
            event = NotificationEvent.objects.get(event_type=event_type, is_active=True)

            # Get appropriate template based on user preferences
            preferences = NotificationPreference.objects.filter(user=recipient).first()
            template = None

            if preferences:
                # Try to find the most appropriate template
                if preferences.email_enabled and event.default_email_template:
                    template = event.default_email_template
                elif preferences.sms_enabled and event.default_sms_template:
                    template = event.default_sms_template
                elif preferences.push_enabled and event.default_push_template:
                    template = event.default_push_template
                elif preferences.in_app_enabled and event.default_in_app_template:
                    template = event.default_in_app_template

            if not template:
                logger.warning(f"No suitable template found for event {event_type}")
                return None

            return NotificationService.create_notification(
                recipient=recipient,
                template=template,
                data=data or {},
                priority=priority,
            )

        except NotificationEvent.DoesNotExist:
            logger.warning(f"Event {event_type} not found or inactive")
            return None
        except Exception as e:
            logger.error(f"Failed to trigger event notification: {e}")
            return None

    @staticmethod
    def send_account_notification(
        recipient: User,
        notification_type: str,
        custom_message: Optional[str] = None,
        priority: str = "medium",
    ) -> Optional[Notification]:
        """Convenience helper to send account-related notifications.

        This will first attempt to use a configured NotificationEvent for the
        given notification_type. If none exists, it will fall back to creating
        (or reusing) a simple email `NotificationTemplate` under the
        `accounts.` namespace and create/send a Notification from it.
        """
        try:
            # Try to map to an event first
            event_map = {
                "welcome": NotificationEvent.EVENT_USER_CREATED,
                "account_activated": NotificationEvent.EVENT_USER_APPROVED,
                "role_changed": NotificationEvent.EVENT_ROLE_CHANGED,
                # Add more mappings if you create corresponding NotificationEvent rows
            }

            event_type = event_map.get(notification_type)
            if event_type:
                notif = NotificationService.trigger_event_notification(
                    event_type=event_type, recipient=recipient, data={"message": custom_message} if custom_message else {}, priority=priority
                )
                if notif:
                    # enqueue send
                    try:
                        from .tasks import send_notification

                        send_notification.delay(str(notif.id))
                    except Exception:
                        logger.exception("Failed to enqueue event notification send task")
                    return notif

            # Fallback: create or get a simple email template for accounts
            template_name = f"accounts.{notification_type}"
            template, _ = NotificationTemplate.objects.get_or_create(
                name=template_name,
                defaults={
                    "template_type": NotificationTemplate.TYPE_EMAIL,
                    "subject": notification_type.replace("_", " ").title(),
                    "body": custom_message or "You have a new account notification.",
                    "is_active": True,
                },
            )

            notif = NotificationService.create_notification(
                recipient=recipient, template=template, data={}, priority=priority
            )

            try:
                from .tasks import send_notification

                send_notification.delay(str(notif.id))
            except Exception:
                logger.exception("Failed to enqueue account notification send task")

            return notif
        except Exception as e:
            logger.error(f"Failed to send account notification: {e}")
            return None


class NotificationAnalytics:
    """Service for notification analytics and reporting"""

    @staticmethod
    def get_delivery_stats(days: int = 30) -> Dict:
        """Get notification delivery statistics"""
        from django.utils import timezone

        since = timezone.now() - timezone.timedelta(days=days)

        notifications = Notification.objects.filter(created_at__gte=since)

        return {
            "total_sent": notifications.count(),
            "delivered": notifications.filter(
                status=Notification.STATUS_DELIVERED
            ).count(),
            "failed": notifications.filter(status=Notification.STATUS_FAILED).count(),
            "pending": notifications.filter(status=Notification.STATUS_PENDING).count(),
            "delivery_rate": 0,  # Calculate based on deliveries
        }

    @staticmethod
    def get_user_engagement_stats(user: User, days: int = 30) -> Dict:
        """Get user engagement statistics"""
        from django.utils import timezone

        since = timezone.now() - timezone.timedelta(days=days)

        notifications = Notification.objects.filter(
            recipient=user, created_at__gte=since
        )

        return {
            "total_received": notifications.count(),
            "read": notifications.filter(status=Notification.STATUS_DELIVERED).count(),
            "unread": notifications.filter(
                status__in=[Notification.STATUS_SENT, Notification.STATUS_PENDING]
            ).count(),
            "engagement_rate": 0,  # Calculate based on read/total
        }
