from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.utils.html import format_html
from django.urls import reverse
from .models import (
    NotificationTemplate,
    Notification,
    NotificationDelivery,
    NotificationPreference,
    NotificationEvent
)


@admin.register(NotificationTemplate)
class NotificationTemplateAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'template_type_badge', 'priority_badge',
        'is_active_badge', 'usage_count', 'created_at'
    )
    list_filter = (
        'template_type', 'priority', 'is_active', 'created_at'
    )
    search_fields = ('name', 'description', 'subject', 'body')
    ordering = ('name',)
    readonly_fields = ('created_at', 'updated_at')
    actions = [
        'activate_templates', 'deactivate_templates', 'duplicate_templates',
        'export_template_data', 'bulk_update_priority'
    ]

    fieldsets = (
        (_('Basic Information'), {
            'fields': ('name', 'description', 'template_type', 'is_active')
        }),
        (_('Template Content'), {
            'fields': ('subject', 'body', 'variables')
        }),
        (_('Settings'), {
            'fields': ('priority',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def template_type_badge(self, obj):
        """Display template type with colored badge"""
        type_colors = {
            'email': 'blue',
            'sms': 'green',
            'push': 'orange',
            'in_app': 'purple'
        }
        color = type_colors.get(obj.template_type, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_template_type_display()
        )
    template_type_badge.short_description = 'Type'

    def priority_badge(self, obj):
        """Display priority with colored badge"""
        priority_colors = {
            'low': 'green',
            'medium': 'orange',
            'high': 'red',
            'urgent': 'darkred'
        }
        color = priority_colors.get(obj.priority, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_priority_display()
        )
    priority_badge.short_description = 'Priority'

    def is_active_badge(self, obj):
        """Display active status with badge"""
        if obj.is_active:
            return format_html(
                '<span style="background-color: green; color: white; padding: 3px 8px; '
                'border-radius: 4px; font-size: 0.8em;">✓ Active</span>'
            )
        return format_html(
            '<span style="background-color: red; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">✗ Inactive</span>'
        )
    is_active_badge.short_description = 'Status'

    def usage_count(self, obj):
        """Count of notifications using this template"""
        count = obj.notifications.count()
        return format_html('<span style="color: #666;">{}</span>', count)
    usage_count.short_description = 'Usage'

    def activate_templates(self, request, queryset):
        """Activate selected templates"""
        updated = queryset.filter(is_active=False).update(is_active=True)
        self.message_user(request, f"Activated {updated} template(s).")
    activate_templates.short_description = "Activate templates"

    def deactivate_templates(self, request, queryset):
        """Deactivate selected templates"""
        updated = queryset.filter(is_active=True).update(is_active=False)
        self.message_user(request, f"Deactivated {updated} template(s).")
    deactivate_templates.short_description = "Deactivate templates"

    def duplicate_templates(self, request, queryset):
        """Duplicate selected templates"""
        duplicated = 0
        for template in queryset:
            template.pk = None
            template.name = f"{template.name} (Copy)"
            template.save()
            duplicated += 1
        self.message_user(request, f"Duplicated {duplicated} template(s).")
    duplicate_templates.short_description = "Duplicate templates"

    def export_template_data(self, request, queryset):
        """Export template data to CSV"""
        import csv
        from django.http import HttpResponse

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="notification_templates.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Name', 'Type', 'Priority', 'Active', 'Subject', 'Body', 'Created At'
        ])

        for template in queryset:
            writer.writerow([
                template.name,
                template.template_type,
                template.priority,
                template.is_active,
                template.subject or '',
                template.body,
                template.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])

        return response
    export_template_data.short_description = "Export template data to CSV"

    def bulk_update_priority(self, request, queryset):
        """Bulk update template priority"""
        if 'apply' in request.POST:
            priority = request.POST.get('priority')
            updated = queryset.update(priority=priority)
            self.message_user(request, f"Updated {updated} template(s) to priority '{priority}'.")
            return

        # Show form
        from django.shortcuts import render
        return render(request, 'admin/bulk_update_priority.html', {
            'templates': queryset,
            'priority_choices': NotificationTemplate._meta.get_field('priority').choices
        })
    bulk_update_priority.short_description = "Bulk update priority"


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = (
        'recipient_link', 'template_link', 'status_badge', 'priority_badge',
        'scheduled_at_display', 'delivery_status', 'created_at'
    )
    list_filter = (
        'status', 'priority', 'template__template_type',
        'scheduled_at', 'sent_at', 'created_at'
    )
    search_fields = (
        'recipient__email', 'recipient__first_name', 'recipient__last_name',
        'subject', 'body', 'template__name'
    )
    ordering = ('-created_at',)
    readonly_fields = ('id', 'created_at', 'updated_at', 'sent_at', 'delivered_at')
    actions = [
        'mark_as_sent', 'mark_as_delivered', 'retry_failed',
        'cancel_notifications', 'export_notification_data', 'bulk_update_priority'
    ]

    fieldsets = (
        (_('Basic Information'), {
            'fields': ('recipient', 'template', 'status', 'priority')
        }),
        (_('Content'), {
            'fields': ('subject', 'body', 'data')
        }),
        (_('Scheduling'), {
            'fields': ('scheduled_at', 'sent_at', 'delivered_at')
        }),
        (_('Related Objects'), {
            'fields': ('content_type', 'object_id', 'related_url')
        }),
        (_('Error Handling'), {
            'fields': ('retry_count', 'max_retries', 'last_error')
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def recipient_link(self, obj):
        """Link to the recipient user"""
        if obj.recipient:
            url = reverse('admin:accounts_user_change', args=[obj.recipient.id])
            return format_html('<a href="{}">{}</a>', url, obj.recipient.email)
        return '-'
    recipient_link.short_description = 'Recipient'

    def template_link(self, obj):
        """Link to the notification template"""
        if obj.template:
            url = reverse('admin:notifications_notificationtemplate_change', args=[obj.template.id])
            return format_html('<a href="{}">{}</a>', url, obj.template.name)
        return '-'
    template_link.short_description = 'Template'

    def status_badge(self, obj):
        """Display status with colored badge"""
        status_colors = {
            'pending': 'gray',
            'sent': 'blue',
            'delivered': 'green',
            'failed': 'red',
            'cancelled': 'orange'
        }
        color = status_colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'

    def priority_badge(self, obj):
        """Display priority with colored badge"""
        priority_colors = {
            'low': 'green',
            'medium': 'orange',
            'high': 'red',
            'urgent': 'darkred'
        }
        color = priority_colors.get(obj.priority, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_priority_display()
        )
    priority_badge.short_description = 'Priority'

    def scheduled_at_display(self, obj):
        """Display scheduled time with status"""
        if obj.scheduled_at:
            if obj.scheduled_at > timezone.now():
                color = 'blue'
                text = obj.scheduled_at.strftime('%Y-%m-%d %H:%M')
            else:
                color = 'orange'
                text = f"Past: {obj.scheduled_at.strftime('%Y-%m-%d %H:%M')}"
            
            return format_html(
                '<span style="background-color: {}; color: white; padding: 3px 8px; '
                'border-radius: 4px; font-size: 0.8em;">{}</span>',
                color, text
            )
        return '-'
    scheduled_at_display.short_description = 'Scheduled'

    def delivery_status(self, obj):
        """Show delivery status summary"""
        deliveries = obj.deliveries.all()
        if not deliveries:
            return format_html('<span style="color: gray;">No deliveries</span>')
        
        delivered = deliveries.filter(status='delivered').count()
        total = deliveries.count()
        
        if delivered == total:
            return format_html('<span style="color: green;">{}/{} ✓</span>', delivered, total)
        elif delivered > 0:
            return format_html('<span style="color: orange;">{}/{} ⚠️</span>', delivered, total)
        else:
            return format_html('<span style="color: red;">{}/{} ✗</span>', delivered, total)
    delivery_status.short_description = 'Delivery'

    def mark_as_sent(self, request, queryset):
        """Mark notifications as sent"""
        updated = queryset.filter(status='pending').update(
            status='sent',
            sent_at=timezone.now()
        )
        self.message_user(request, f"Marked {updated} notification(s) as sent.")
    mark_as_sent.short_description = "Mark as sent"

    def mark_as_delivered(self, request, queryset):
        """Mark notifications as delivered"""
        updated = queryset.filter(status__in=['pending', 'sent']).update(
            status='delivered',
            delivered_at=timezone.now()
        )
        self.message_user(request, f"Marked {updated} notification(s) as delivered.")
    mark_as_delivered.short_description = "Mark as delivered"

    def retry_failed(self, request, queryset):
        """Retry failed notifications"""
        updated = queryset.filter(status='failed').update(
            status='pending',
            retry_count=0,
            last_error=''
        )
        self.message_user(request, f"Queued {updated} notification(s) for retry.")
    retry_failed.short_description = "Retry failed notifications"

    def cancel_notifications(self, request, queryset):
        """Cancel pending notifications"""
        updated = queryset.filter(status='pending').update(status='cancelled')
        self.message_user(request, f"Cancelled {updated} notification(s).")
    cancel_notifications.short_description = "Cancel notifications"

    def export_notification_data(self, request, queryset):
        """Export notification data to CSV"""
        import csv
        from django.http import HttpResponse

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="notifications.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Recipient', 'Template', 'Status', 'Priority', 'Subject',
            'Scheduled At', 'Sent At', 'Created At'
        ])

        for notification in queryset.select_related('recipient', 'template'):
            writer.writerow([
                notification.recipient.email if notification.recipient else '',
                notification.template.name if notification.template else '',
                notification.status,
                notification.priority,
                notification.subject or '',
                notification.scheduled_at.strftime('%Y-%m-%d %H:%M:%S') if notification.scheduled_at else '',
                notification.sent_at.strftime('%Y-%m-%d %H:%M:%S') if notification.sent_at else '',
                notification.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])

        return response
    export_notification_data.short_description = "Export notification data to CSV"

    def bulk_update_priority(self, request, queryset):
        """Bulk update notification priority"""
        if 'apply' in request.POST:
            priority = request.POST.get('priority')
            updated = queryset.update(priority=priority)
            self.message_user(request, f"Updated {updated} notification(s) to priority '{priority}'.")
            return

        # Show form
        from django.shortcuts import render
        return render(request, 'admin/bulk_update_notification_priority.html', {
            'notifications': queryset,
            'priority_choices': Notification._meta.get_field('priority').choices
        })
    bulk_update_priority.short_description = "Bulk update priority"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('recipient', 'template')


@admin.register(NotificationDelivery)
class NotificationDeliveryAdmin(admin.ModelAdmin):
    list_display = (
        'notification_link', 'delivery_method_badge', 'status_badge',
        'provider_display', 'recipient_address_preview', 'sent_at', 'created_at'
    )
    list_filter = (
        'delivery_method', 'status', 'provider', 'sent_at', 'created_at'
    )
    search_fields = (
        'notification__recipient__email', 'provider_message_id',
        'recipient_address', 'notification__subject'
    )
    ordering = ('-created_at',)
    readonly_fields = ('id', 'created_at', 'updated_at')
    actions = [
        'mark_as_delivered', 'retry_failed_deliveries', 'export_delivery_data'
    ]

    fieldsets = (
        (_('Basic Information'), {
            'fields': ('notification', 'delivery_method', 'status')
        }),
        (_('Delivery Details'), {
            'fields': ('provider', 'provider_message_id', 'recipient_address')
        }),
        (_('Timing'), {
            'fields': ('sent_at', 'delivered_at')
        }),
        (_('Error Handling'), {
            'fields': ('error_message', 'retry_count')
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def notification_link(self, obj):
        """Link to the notification"""
        if obj.notification:
            url = reverse('admin:notifications_notification_change', args=[obj.notification.id])
            return format_html('<a href="{}">Notification #{}</a>', url, obj.notification.id)
        return '-'
    notification_link.short_description = 'Notification'

    def delivery_method_badge(self, obj):
        """Display delivery method with colored badge"""
        method_colors = {
            'email': 'blue',
            'sms': 'green',
            'push': 'orange',
            'in_app': 'purple'
        }
        color = method_colors.get(obj.delivery_method, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_delivery_method_display()
        )
    delivery_method_badge.short_description = 'Method'

    def status_badge(self, obj):
        """Display status with colored badge"""
        status_colors = {
            'pending': 'gray',
            'sent': 'blue',
            'delivered': 'green',
            'failed': 'red',
            'bounced': 'darkred'
        }
        color = status_colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'

    def provider_display(self, obj):
        """Display provider with icon"""
        if obj.provider:
            return format_html('<span style="font-weight: bold;">{}</span>', obj.provider.title())
        return '-'
    provider_display.short_description = 'Provider'

    def recipient_address_preview(self, obj):
        """Preview of recipient address (masked for privacy)"""
        if obj.recipient_address:
            if '@' in obj.recipient_address:  # Email
                local, domain = obj.recipient_address.split('@', 1)
                masked = local[:2] + '***' + local[-1] if len(local) > 3 else local
                return f"{masked}@{domain}"
            elif obj.recipient_address.startswith('+'):  # Phone
                return obj.recipient_address[:4] + '***' + obj.recipient_address[-3:]
            else:  # Other (device token, etc.)
                return obj.recipient_address[:10] + '...' if len(obj.recipient_address) > 10 else obj.recipient_address
        return '-'
    recipient_address_preview.short_description = 'Recipient'

    def mark_as_delivered(self, request, queryset):
        """Mark deliveries as delivered"""
        updated = queryset.filter(status__in=['pending', 'sent']).update(
            status='delivered',
            delivered_at=timezone.now()
        )
        self.message_user(request, f"Marked {updated} delivery(ies) as delivered.")
    mark_as_delivered.short_description = "Mark as delivered"

    def retry_failed_deliveries(self, request, queryset):
        """Retry failed deliveries"""
        updated = queryset.filter(status__in=['failed', 'bounced']).update(
            status='pending',
            retry_count=0,
            error_message=''
        )
        self.message_user(request, f"Queued {updated} delivery(ies) for retry.")
    retry_failed_deliveries.short_description = "Retry failed deliveries"

    def export_delivery_data(self, request, queryset):
        """Export delivery data to CSV"""
        import csv
        from django.http import HttpResponse

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="notification_deliveries.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Notification ID', 'Method', 'Status', 'Provider',
            'Recipient Address', 'Sent At', 'Delivered At', 'Created At'
        ])

        for delivery in queryset.select_related('notification'):
            writer.writerow([
                delivery.notification.id if delivery.notification else '',
                delivery.delivery_method,
                delivery.status,
                delivery.provider or '',
                delivery.recipient_address,
                delivery.sent_at.strftime('%Y-%m-%d %H:%M:%S') if delivery.sent_at else '',
                delivery.delivered_at.strftime('%Y-%m-%d %H:%M:%S') if delivery.delivered_at else '',
                delivery.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])

        return response
    export_delivery_data.short_description = "Export delivery data to CSV"


@admin.register(NotificationPreference)
class NotificationPreferenceAdmin(admin.ModelAdmin):
    list_display = (
        'user_link', 'channel_summary', 'category_summary',
        'quiet_hours_display', 'contact_info_summary'
    )
    list_filter = (
        'email_enabled', 'sms_enabled', 'push_enabled', 'in_app_enabled',
        'exam_notifications', 'moderation_notifications', 'system_notifications'
    )
    search_fields = (
        'user__email', 'user__first_name', 'user__last_name',
        'email_address', 'phone_number'
    )
    ordering = ('user__email',)
    readonly_fields = ('created_at', 'updated_at')
    actions = [
        'enable_all_channels', 'disable_all_channels', 'reset_to_defaults',
        'export_preferences_data', 'bulk_update_channels'
    ]

    fieldsets = (
        (_('User'), {
            'fields': ('user',)
        }),
        (_('Channel Preferences'), {
            'fields': ('email_enabled', 'sms_enabled', 'push_enabled', 'in_app_enabled')
        }),
        (_('Category Preferences'), {
            'fields': ('exam_notifications', 'moderation_notifications',
                      'system_notifications', 'deadline_notifications')
        }),
        (_('Quiet Hours'), {
            'fields': ('quiet_hours_start', 'quiet_hours_end')
        }),
        (_('Contact Information'), {
            'fields': ('email_address', 'phone_number', 'device_tokens')
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def user_link(self, obj):
        """Link to the user"""
        if obj.user:
            url = reverse('admin:accounts_user_change', args=[obj.user.id])
            return format_html('<a href="{}">{}</a>', url, obj.user.email)
        return '-'
    user_link.short_description = 'User'

    def channel_summary(self, obj):
        """Summary of enabled channels"""
        channels = []
        if obj.email_enabled:
            channels.append('<span style="color: blue;">📧</span>')
        if obj.sms_enabled:
            channels.append('<span style="color: green;">📱</span>')
        if obj.push_enabled:
            channels.append('<span style="color: orange;">🔔</span>')
        if obj.in_app_enabled:
            channels.append('<span style="color: purple;">💬</span>')
        
        if channels:
            return format_html(' '.join(channels))
        return format_html('<span style="color: gray;">None</span>')
    channel_summary.short_description = 'Channels'

    def category_summary(self, obj):
        """Summary of enabled categories"""
        categories = []
        if obj.exam_notifications:
            categories.append('Exams')
        if obj.moderation_notifications:
            categories.append('Mod.')
        if obj.system_notifications:
            categories.append('System')
        if obj.deadline_notifications:
            categories.append('Deadlines')
        
        if categories:
            return format_html('<span style="font-size: 0.8em;">{}</span>', ', '.join(categories))
        return format_html('<span style="color: gray; font-size: 0.8em;">None</span>')
    category_summary.short_description = 'Categories'

    def quiet_hours_display(self, obj):
        """Display quiet hours"""
        if obj.quiet_hours_start and obj.quiet_hours_end:
            return format_html(
                '<span style="font-size: 0.8em;">{} - {}</span>',
                obj.quiet_hours_start.strftime('%H:%M'),
                obj.quiet_hours_end.strftime('%H:%M')
            )
        return format_html('<span style="color: gray; font-size: 0.8em;">Not set</span>')
    quiet_hours_display.short_description = 'Quiet Hours'

    def contact_info_summary(self, obj):
        """Summary of contact information"""
        contacts = []
        if obj.email_address:
            contacts.append('📧')
        if obj.phone_number:
            contacts.append('📱')
        if obj.device_tokens:
            contacts.append(f'🔔({len(obj.device_tokens)})')
        
        if contacts:
            return format_html(' '.join(contacts))
        return format_html('<span style="color: gray;">None</span>')
    contact_info_summary.short_description = 'Contacts'

    def enable_all_channels(self, request, queryset):
        """Enable all notification channels"""
        updated = queryset.update(
            email_enabled=True,
            sms_enabled=True,
            push_enabled=True,
            in_app_enabled=True
        )
        self.message_user(request, f"Enabled all channels for {updated} user(s).")
    enable_all_channels.short_description = "Enable all channels"

    def disable_all_channels(self, request, queryset):
        """Disable all notification channels"""
        updated = queryset.update(
            email_enabled=False,
            sms_enabled=False,
            push_enabled=False,
            in_app_enabled=False
        )
        self.message_user(request, f"Disabled all channels for {updated} user(s).")
    disable_all_channels.short_description = "Disable all channels"

    def reset_to_defaults(self, request, queryset):
        """Reset preferences to defaults"""
        updated = queryset.update(
            email_enabled=True,
            sms_enabled=False,
            push_enabled=True,
            in_app_enabled=True,
            exam_notifications=True,
            moderation_notifications=True,
            system_notifications=True,
            deadline_notifications=True,
            quiet_hours_start=None,
            quiet_hours_end=None
        )
        self.message_user(request, f"Reset {updated} user preference(s) to defaults.")
    reset_to_defaults.short_description = "Reset to defaults"

    def export_preferences_data(self, request, queryset):
        """Export preferences data to CSV"""
        import csv
        from django.http import HttpResponse

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="notification_preferences.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'User', 'Email Enabled', 'SMS Enabled', 'Push Enabled', 'In-App Enabled',
            'Exam Notifications', 'Moderation Notifications', 'System Notifications',
            'Deadline Notifications', 'Quiet Hours Start', 'Quiet Hours End'
        ])

        for pref in queryset.select_related('user'):
            writer.writerow([
                pref.user.email if pref.user else '',
                pref.email_enabled,
                pref.sms_enabled,
                pref.push_enabled,
                pref.in_app_enabled,
                pref.exam_notifications,
                pref.moderation_notifications,
                pref.system_notifications,
                pref.deadline_notifications,
                pref.quiet_hours_start.strftime('%H:%M') if pref.quiet_hours_start else '',
                pref.quiet_hours_end.strftime('%H:%M') if pref.quiet_hours_end else ''
            ])

        return response
    export_preferences_data.short_description = "Export preferences data to CSV"

    def bulk_update_channels(self, request, queryset):
        """Bulk update channel preferences"""
        if 'apply' in request.POST:
            email = request.POST.get('email_enabled') == 'on'
            sms = request.POST.get('sms_enabled') == 'on'
            push = request.POST.get('push_enabled') == 'on'
            in_app = request.POST.get('in_app_enabled') == 'on'
            
            updated = queryset.update(
                email_enabled=email,
                sms_enabled=sms,
                push_enabled=push,
                in_app_enabled=in_app
            )
            self.message_user(request, f"Updated channels for {updated} user(s).")
            return

        # Show form
        from django.shortcuts import render
        return render(request, 'admin/bulk_update_channels.html', {
            'preferences': queryset
        })
    bulk_update_channels.short_description = "Bulk update channels"


@admin.register(NotificationEvent)
class NotificationEventAdmin(admin.ModelAdmin):
    list_display = (
        'event_type_badge', 'name', 'is_active_badge',
        'template_summary', 'created_at'
    )
    list_filter = ('event_type', 'is_active', 'created_at')
    search_fields = ('name', 'description', 'event_type')
    ordering = ('event_type',)
    readonly_fields = ('created_at', 'updated_at')
    actions = [
        'activate_events', 'deactivate_events', 'export_event_data'
    ]

    fieldsets = (
        (_('Basic Information'), {
            'fields': ('event_type', 'name', 'description', 'is_active')
        }),
        (_('Default Templates'), {
            'fields': ('default_email_template', 'default_sms_template',
                      'default_push_template', 'default_in_app_template')
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def event_type_badge(self, obj):
        """Display event type with colored badge"""
        type_colors = {
            'exam_created': 'blue',
            'exam_submitted': 'green',
            'exam_reviewed': 'orange',
            'exam_approved': 'teal',
            'moderation_assigned': 'purple',
            'moderation_completed': 'indigo',
            'deadline_approaching': 'yellow',
            'deadline_overdue': 'red'
        }
        color = type_colors.get(obj.event_type, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_event_type_display()
        )
    event_type_badge.short_description = 'Event Type'

    def is_active_badge(self, obj):
        """Display active status with badge"""
        if obj.is_active:
            return format_html(
                '<span style="background-color: green; color: white; padding: 3px 8px; '
                'border-radius: 4px; font-size: 0.8em;">✓ Active</span>'
            )
        return format_html(
            '<span style="background-color: red; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">✗ Inactive</span>'
        )
    is_active_badge.short_description = 'Status'

    def template_summary(self, obj):
        """Summary of assigned templates"""
        templates = []
        if obj.default_email_template:
            templates.append('📧')
        if obj.default_sms_template:
            templates.append('📱')
        if obj.default_push_template:
            templates.append('🔔')
        if obj.default_in_app_template:
            templates.append('💬')
        
        if templates:
            return format_html(' '.join(templates))
        return format_html('<span style="color: gray;">None</span>')
    template_summary.short_description = 'Templates'

    def activate_events(self, request, queryset):
        """Activate selected events"""
        updated = queryset.filter(is_active=False).update(is_active=True)
        self.message_user(request, f"Activated {updated} event(s).")
    activate_events.short_description = "Activate events"

    def deactivate_events(self, request, queryset):
        """Deactivate selected events"""
        updated = queryset.filter(is_active=True).update(is_active=False)
        self.message_user(request, f"Deactivated {updated} event(s).")
    deactivate_events.short_description = "Deactivate events"

    def export_event_data(self, request, queryset):
        """Export event data to CSV"""
        import csv
        from django.http import HttpResponse

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="notification_events.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Event Type', 'Name', 'Description', 'Active',
            'Email Template', 'SMS Template', 'Push Template', 'In-App Template'
        ])

        for event in queryset.select_related(
            'default_email_template', 'default_sms_template',
            'default_push_template', 'default_in_app_template'
        ):
            writer.writerow([
                event.event_type,
                event.name,
                event.description or '',
                event.is_active,
                event.default_email_template.name if event.default_email_template else '',
                event.default_sms_template.name if event.default_sms_template else '',
                event.default_push_template.name if event.default_push_template else '',
                event.default_in_app_template.name if event.default_in_app_template else ''
            ])

        return response
    export_event_data.short_description = "Export event data to CSV"
