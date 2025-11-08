from celery import shared_task
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import SecurityEvent, APIKey, AuditLog
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def process_security_event(self, event_id):
    """Process security event and take appropriate actions"""
    try:
        event = SecurityEvent.objects.get(id=event_id)

        if event.status != SecurityEvent.STATUS_PENDING:
            logger.warning(f"Event {event_id} is not pending, skipping")
            return

        logger.info(f"Processing security event: {event.event_type} ({event_id})")

        # Process based on event type
        if event.event_type == SecurityEvent.TYPE_SUSPICIOUS_LOGIN:
            handle_suspicious_login(event)
        elif event.event_type == SecurityEvent.TYPE_FAILED_LOGIN:
            handle_failed_login(event)
        elif event.event_type == SecurityEvent.TYPE_UNAUTHORIZED_ACCESS:
            handle_unauthorized_access(event)
        elif event.event_type == SecurityEvent.TYPE_RATE_LIMIT_EXCEEDED:
            handle_rate_limit_exceeded(event)

        # Update event status
        event.status = SecurityEvent.STATUS_PROCESSED
        event.processed_at = timezone.now()
        event.save()

        logger.info(f"Security event {event_id} processed successfully")

    except SecurityEvent.DoesNotExist:
        logger.error(f"Security event {event_id} does not exist")
    except Exception as exc:
        logger.error(f"Failed to process security event {event_id}: {str(exc)}")
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))


def handle_suspicious_login(event):
    """Handle suspicious login attempt"""
    # Send alert to security team
    alert_subject = f"Suspicious Login Detected: {event.user.get_username() if event.user else 'Unknown'}"
    alert_message = f"""
    Suspicious login detected:
    User: {event.user.get_username() if event.user else 'Unknown'}
    IP: {event.ip_address}
    User Agent: {event.user_agent}
    Location: {event.location or 'Unknown'}
    Time: {event.timestamp}
    """

    send_security_alert(alert_subject, alert_message)

    # Could also temporarily lock account, require 2FA, etc.


def handle_failed_login(event):
    """Handle failed login attempt"""
    # Track consecutive failures
    recent_failures = SecurityEvent.objects.filter(
        event_type=SecurityEvent.TYPE_FAILED_LOGIN,
        ip_address=event.ip_address,
        timestamp__gte=timezone.now() - timezone.timedelta(hours=1)
    ).count()

    if recent_failures >= 5:
        # Implement progressive delays or temporary blocks
        logger.warning(f"Multiple failed login attempts from IP: {event.ip_address}")


def handle_unauthorized_access(event):
    """Handle unauthorized access attempt"""
    # Log and alert
    alert_subject = f"Unauthorized Access Attempt"
    alert_message = f"""
    Unauthorized access attempt:
    User: {event.user.get_username() if event.user else 'Unknown'}
    IP: {event.ip_address}
    Resource: {event.resource}
    Action: {event.action}
    Time: {event.timestamp}
    """

    send_security_alert(alert_subject, alert_message)


def handle_rate_limit_exceeded(event):
    """Handle rate limit exceeded"""
    # Could implement temporary IP blocks or additional monitoring
    logger.warning(f"Rate limit exceeded by IP: {event.ip_address}")


def send_security_alert(subject, message):
    """Send security alert to administrators"""
    try:
        # Get admin emails - this would be configurable
        admin_emails = [admin.email for admin in User.objects.filter(is_superuser=True)]

        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=admin_emails,
            fail_silently=False,
        )

        logger.info(f"Security alert sent to {len(admin_emails)} administrators")

    except Exception as exc:
        logger.error(f"Failed to send security alert: {str(exc)}")


@shared_task(bind=True, max_retries=3)
def rotate_api_keys(self):
    """Rotate expired or compromised API keys"""
    try:
        # Find keys that need rotation
        expired_keys = APIKey.objects.filter(
            expires_at__lt=timezone.now(),
            status=APIKey.STATUS_ACTIVE
        )

        compromised_keys = APIKey.objects.filter(
            status=APIKey.STATUS_COMPROMISED
        )

        rotated_count = 0

        for api_key in list(expired_keys) + list(compromised_keys):
            # Generate new key
            new_key = APIKey.generate_key()

            # Create audit log
            AuditLog.objects.create(
                user=api_key.user,
                action=AuditLog.ACTION_KEY_ROTATED,
                resource_type='APIKey',
                resource_id=str(api_key.id),
                details=f"API key rotated. Old key: {api_key.key[:8]}..."
            )

            # Update key
            api_key.key = new_key
            api_key.expires_at = timezone.now() + timezone.timedelta(days=365)  # 1 year
            api_key.status = APIKey.STATUS_ACTIVE
            api_key.save()

            rotated_count += 1

            # Notify user
            try:
                send_mail(
                    subject="API Key Rotated",
                    message=f"Your API key has been automatically rotated. New key: {new_key}",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[api_key.user.email],
                    fail_silently=False,
                )
            except Exception as exc:
                logger.error(f"Failed to notify user of key rotation: {str(exc)}")

        logger.info(f"Rotated {rotated_count} API keys")

    except Exception as exc:
        logger.error(f"Failed to rotate API keys: {str(exc)}")
        raise self.retry(exc=exc, countdown=3600)  # Retry in 1 hour


@shared_task
def cleanup_security_events():
    """Clean up old security events"""
    cutoff_date = timezone.now() - timezone.timedelta(days=90)
    deleted_count, _ = SecurityEvent.objects.filter(timestamp__lt=cutoff_date).delete()

    logger.info(f"Cleaned up {deleted_count} old security events")
    return deleted_count


@shared_task
def generate_security_report():
    """Generate daily security report"""
    try:
        # Calculate report period (last 24 hours)
        since = timezone.now() - timezone.timedelta(days=1)

        report_data = {
            'period': f"{since.date()} to {timezone.now().date()}",
            'total_events': SecurityEvent.objects.filter(timestamp__gte=since).count(),
            'events_by_type': list(SecurityEvent.objects.filter(timestamp__gte=since)
                                  .values('event_type')
                                  .annotate(count=Count('id'))
                                  .order_by('-count')),
            'suspicious_activities': SecurityEvent.objects.filter(
                timestamp__gte=since,
                severity__in=['HIGH', 'CRITICAL']
            ).count(),
            'blocked_ips': SecurityEvent.objects.filter(
                timestamp__gte=since,
                action_taken='BLOCKED'
            ).values('ip_address').distinct().count(),
            'top_attack_sources': list(SecurityEvent.objects.filter(timestamp__gte=since)
                                     .values('ip_address')
                                     .annotate(count=Count('id'))
                                     .order_by('-count')[:10])
        }

        # Send report to security team
        subject = f"Daily Security Report - {timezone.now().date()}"
        message = f"""
        Daily Security Report

        Period: {report_data['period']}
        Total Events: {report_data['total_events']}
        Suspicious Activities: {report_data['suspicious_activities']}
        Blocked IPs: {report_data['blocked_ips']}

        Events by Type:
        {chr(10).join([f"- {item['event_type']}: {item['count']}" for item in report_data['events_by_type']])}

        Top Attack Sources:
        {chr(10).join([f"- {item['ip_address']}: {item['count']}" for item in report_data['top_attack_sources']])}
        """

        send_security_alert(subject, message)

        logger.info("Daily security report generated and sent")

    except Exception as exc:
        logger.error(f"Failed to generate security report: {str(exc)}")


@shared_task(bind=True, max_retries=3)
def monitor_api_key_usage(self):
    """Monitor API key usage and detect anomalies"""
    try:
        # Check for unusual API key activity
        since = timezone.now() - timezone.timedelta(hours=1)

        # Find keys with high usage
        high_usage_keys = APIKey.objects.filter(
            last_used_at__gte=since
        ).order_by('-usage_count')[:10]

        for api_key in high_usage_keys:
            # Check if usage is above threshold
            if api_key.usage_count > 1000:  # Configurable threshold
                logger.warning(f"High API key usage detected: {api_key.name} ({api_key.usage_count} requests)")

                # Could implement rate limiting or alerts

        # Reset usage counts periodically
        APIKey.objects.filter(last_used_at__lt=since).update(usage_count=0)

        logger.info("API key usage monitoring completed")

    except Exception as exc:
        logger.error(f"Failed to monitor API key usage: {str(exc)}")
        raise self.retry(exc=exc, countdown=3600)


@shared_task
def audit_log_cleanup():
    """Clean up old audit logs based on retention policy"""
    # Keep audit logs for 1 year
    cutoff_date = timezone.now() - timezone.timedelta(days=365)
    deleted_count, _ = AuditLog.objects.filter(timestamp__lt=cutoff_date).delete()

    logger.info(f"Cleaned up {deleted_count} old audit log entries")
    return deleted_count