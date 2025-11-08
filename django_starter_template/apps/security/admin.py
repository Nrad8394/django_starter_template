from django.contrib import admin
from django.utils.translation import gettext_lazy as _, ngettext
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import AuditLog, RateLimit, SecurityEvent, SecuritySettings, APIKey


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        'timestamp', 'user_link', 'event_type_badge', 'severity_badge',
        'ip_address_display', 'request_path_preview', 'response_status_badge'
    )
    list_filter = (
        'event_type', 'severity', 'timestamp', 'user', 'request_method'
    )
    search_fields = (
        'user__email', 'user__first_name', 'user__last_name',
        'description', 'ip_address', 'request_path', 'session_key'
    )
    readonly_fields = ('id', 'timestamp')
    ordering = ('-timestamp',)
    actions = [
        'export_audit_data', 'filter_by_severity', 'filter_security_events'
    ]

    fieldsets = (
        (_('Basic Information'), {
            'fields': ('id', 'user', 'event_type', 'severity', 'description', 'timestamp')
        }),
        (_('Request Details'), {
            'fields': ('ip_address', 'user_agent', 'session_key', 'request_path', 'request_method'),
            'classes': ('collapse',)
        }),
        (_('Data'), {
            'fields': ('request_data', 'response_status', 'additional_data'),
            'classes': ('collapse',)
        }),
    )

    def user_link(self, obj):
        """Link to the user who performed the action"""
        if obj.user:
            url = reverse('admin:accounts_user_change', args=[obj.user.id])
            return format_html('<a href="{}">{}</a>', url, obj.user.email)
        return format_html('<span style="color: gray;">Anonymous</span>')
    user_link.short_description = 'User'

    def event_type_badge(self, obj):
        """Display event type with colored badge"""
        type_colors = {
            'login': 'green',
            'logout': 'blue',
            'password_change': 'orange',
            'password_reset': 'purple',
            'profile_update': 'teal',
            'permission_change': 'red',
            'data_access': 'indigo',
            'data_modification': 'yellow',
            'security_violation': 'darkred',
            'unauthorized_access': 'red',
            'api_access': 'cyan',
            'failed_login': 'orange',
            'suspicious_activity': 'red'
        }
        color = type_colors.get(obj.event_type, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_event_type_display()
        )
    event_type_badge.short_description = 'Event'

    def severity_badge(self, obj):
        """Display severity with colored badge"""
        severity_colors = {
            'low': 'green',
            'medium': 'orange',
            'high': 'red',
            'critical': 'darkred'
        }
        color = severity_colors.get(obj.severity, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_severity_display()
        )
    severity_badge.short_description = 'Severity'

    def ip_address_display(self, obj):
        """Display IP address with geolocation hint"""
        if obj.ip_address:
            return format_html('<code>{}</code>', obj.ip_address)
        return '-'
    ip_address_display.short_description = 'IP Address'

    def request_path_preview(self, obj):
        """Preview of request path"""
        if obj.request_path:
            preview = obj.request_path[:50] + '...' if len(obj.request_path) > 50 else obj.request_path
            return format_html('<span title="{}">{}</span>', obj.request_path, preview)
        return '-'
    request_path_preview.short_description = 'Path'

    def response_status_badge(self, obj):
        """Display HTTP response status with color coding"""
        if obj.response_status:
            if obj.response_status >= 500:
                color = 'darkred'
            elif obj.response_status >= 400:
                color = 'red'
            elif obj.response_status >= 300:
                color = 'orange'
            elif obj.response_status >= 200:
                color = 'green'
            else:
                color = 'gray'
            
            return format_html(
                '<span style="background-color: {}; color: white; padding: 3px 8px; '
                'border-radius: 4px; font-size: 0.8em;">{}</span>',
                color, obj.response_status
            )
        return '-'
    response_status_badge.short_description = 'Status'

    def export_audit_data(self, request, queryset):
        """Export audit log data to CSV"""
        import csv
        from django.http import HttpResponse

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="audit_logs.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Timestamp', 'User', 'Event Type', 'Severity', 'Description',
            'IP Address', 'Request Path', 'Response Status'
        ])

        for log in queryset.select_related('user'):
            writer.writerow([
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.user.email if log.user else 'Anonymous',
                log.event_type,
                log.severity,
                log.description,
                log.ip_address or '',
                log.request_path or '',
                log.response_status or ''
            ])

        return response
    export_audit_data.short_description = "Export audit data to CSV"

    def filter_by_severity(self, request, queryset):
        """Filter logs by severity level"""
        # This could implement custom filtering logic
        self.message_user(request, f"Filtered {queryset.count()} log(s) by severity.")
    filter_by_severity.short_description = "Filter by severity"

    def filter_security_events(self, request, queryset):
        """Filter to show only security-related events"""
        security_events = ['security_violation', 'unauthorized_access', 'failed_login', 'suspicious_activity']
        filtered = queryset.filter(event_type__in=security_events)
        self.message_user(request, f"Showing {filtered.count()} security-related event(s).")
    filter_security_events.short_description = "Show security events only"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(RateLimit)
class RateLimitAdmin(admin.ModelAdmin):
    list_display = (
        'limit_type_badge', 'identifier_display', 'endpoint_preview',
        'request_count_display', 'window_status', 'block_status_badge'
    )
    list_filter = (
        'limit_type', 'is_blocked', 'endpoint', 'window_start'
    )
    search_fields = ('identifier', 'endpoint')
    readonly_fields = ('id', 'window_start', 'window_end')
    ordering = ('-window_start',)
    actions = [
        'unblock_limits', 'reset_counters', 'export_rate_limit_data'
    ]

    fieldsets = (
        (_('Basic Information'), {
            'fields': ('id', 'limit_type', 'identifier', 'endpoint')
        }),
        (_('Rate Limiting'), {
            'fields': ('request_count', 'window_start', 'window_end', 'is_blocked', 'blocked_until')
        }),
    )

    def limit_type_badge(self, obj):
        """Display limit type with colored badge"""
        type_colors = {
            'ip': 'blue',
            'user': 'green',
            'api_key': 'orange'
        }
        color = type_colors.get(obj.limit_type, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_limit_type_display()
        )
    limit_type_badge.short_description = 'Type'

    def identifier_display(self, obj):
        """Display identifier with type-specific formatting"""
        if obj.limit_type == 'ip':
            return format_html('<code>{}</code>', obj.identifier)
        elif obj.limit_type == 'user':
            # Try to get user email if it's a user ID
            try:
                from django.contrib.auth import get_user_model
                User = get_user_model()
                user = User.objects.get(id=obj.identifier)
                return format_html('<a href="{}">{}</a>', 
                    reverse('admin:accounts_user_change', args=[user.id]), user.email)
            except:
                return obj.identifier
        else:
            return format_html('<code>{}</code>', obj.identifier[:20] + '...' if len(obj.identifier) > 20 else obj.identifier)
    identifier_display.short_description = 'Identifier'

    def endpoint_preview(self, obj):
        """Preview of endpoint path"""
        preview = obj.endpoint[:40] + '...' if len(obj.endpoint) > 40 else obj.endpoint
        return format_html('<span title="{}">{}</span>', obj.endpoint, preview)
    endpoint_preview.short_description = 'Endpoint'

    def request_count_display(self, obj):
        """Display request count with threshold coloring"""
        count = obj.request_count
        if count > 100:
            color = 'red'
        elif count > 50:
            color = 'orange'
        else:
            color = 'green'
        
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, count
        )
    request_count_display.short_description = 'Requests'

    def window_status(self, obj):
        """Display window status"""
        now = timezone.now()
        if now > obj.window_end:
            return format_html('<span style="color: gray;">Expired</span>')
        elif now < obj.window_start:
            return format_html('<span style="color: blue;">Future</span>')
        else:
            remaining = obj.window_end - now
            minutes = int(remaining.total_seconds() / 60)
            return format_html('<span style="color: green;">{} min left</span>', minutes)
    window_status.short_description = 'Window'

    def block_status_badge(self, obj):
        """Display block status with badge"""
        if obj.is_blocked:
            if obj.blocked_until and obj.blocked_until > timezone.now():
                return format_html(
                    '<span style="background-color: red; color: white; padding: 3px 8px; '
                    'border-radius: 4px; font-size: 0.8em;">Blocked until {}</span>',
                    obj.blocked_until.strftime('%H:%M')
                )
            else:
                return format_html(
                    '<span style="background-color: orange; color: white; padding: 3px 8px; '
                    'border-radius: 4px; font-size: 0.8em;">Blocked</span>'
                )
        return format_html(
            '<span style="background-color: green; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">Active</span>'
        )
    block_status_badge.short_description = 'Status'

    def unblock_limits(self, request, queryset):
        """Unblock selected rate limits"""
        updated = queryset.filter(is_blocked=True).update(
            is_blocked=False,
            blocked_until=None
        )
        self.message_user(request, f"Unblocked {updated} rate limit(s).")
    unblock_limits.short_description = "Unblock selected limits"

    def reset_counters(self, request, queryset):
        """Reset request counters"""
        updated = queryset.update(request_count=0)
        self.message_user(request, f"Reset counters for {updated} rate limit(s).")
    reset_counters.short_description = "Reset counters"

    def export_rate_limit_data(self, request, queryset):
        """Export rate limit data to CSV"""
        import csv
        from django.http import HttpResponse

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="rate_limits.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Type', 'Identifier', 'Endpoint', 'Request Count',
            'Window Start', 'Window End', 'Is Blocked', 'Blocked Until'
        ])

        for limit in queryset:
            writer.writerow([
                limit.limit_type,
                limit.identifier,
                limit.endpoint,
                limit.request_count,
                limit.window_start.strftime('%Y-%m-%d %H:%M:%S'),
                limit.window_end.strftime('%Y-%m-%d %H:%M:%S'),
                limit.is_blocked,
                limit.blocked_until.strftime('%Y-%m-%d %H:%M:%S') if limit.blocked_until else ''
            ])

        return response
    export_rate_limit_data.short_description = "Export rate limit data to CSV"

    def has_add_permission(self, request):
        return False


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = (
        'event_type_badge', 'title', 'severity_badge', 'status_badge',
        'user_link', 'ip_address_display', 'created_at', 'resolution_status'
    )
    list_filter = (
        'event_type', 'severity', 'status', 'created_at', 'resolved_at'
    )
    search_fields = (
        'title', 'description', 'user__email', 'user__first_name', 'user__last_name',
        'ip_address', 'resolution_notes'
    )
    readonly_fields = ('id', 'created_at', 'updated_at')
    ordering = ('-created_at',)
    actions = [
        'mark_as_resolved', 'mark_as_false_positive', 'mark_as_ignored',
        'export_security_events', 'bulk_resolve_with_note'
    ]

    fieldsets = (
        (_('Basic Information'), {
            'fields': ('id', 'event_type', 'status', 'title', 'description', 'severity')
        }),
        (_('Details'), {
            'fields': ('ip_address', 'user', 'detection_data'),
            'classes': ('collapse',)
        }),
        (_('Resolution'), {
            'fields': ('resolution_notes', 'resolved_by', 'resolved_at'),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def event_type_badge(self, obj):
        """Display event type with colored badge"""
        type_colors = {
            'brute_force': 'red',
            'sql_injection': 'darkred',
            'xss': 'orange',
            'csrf': 'purple',
            'unauthorized_access': 'red',
            'suspicious_ip': 'orange',
            'malware_upload': 'darkred',
            'data_breach': 'red',
            'api_abuse': 'orange'
        }
        color = type_colors.get(obj.event_type, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_event_type_display()
        )
    event_type_badge.short_description = 'Event Type'

    def severity_badge(self, obj):
        """Display severity with colored badge"""
        severity_colors = {
            'low': 'green',
            'medium': 'orange',
            'high': 'red',
            'critical': 'darkred'
        }
        color = severity_colors.get(obj.severity, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_severity_display()
        )
    severity_badge.short_description = 'Severity'

    def status_badge(self, obj):
        """Display status with colored badge"""
        status_colors = {
            'active': 'red',
            'resolved': 'green',
            'false_positive': 'orange',
            'ignored': 'gray'
        }
        color = status_colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'

    def user_link(self, obj):
        """Link to the user associated with the event"""
        if obj.user:
            url = reverse('admin:accounts_user_change', args=[obj.user.id])
            return format_html('<a href="{}">{}</a>', url, obj.user.email)
        return format_html('<span style="color: gray;">N/A</span>')
    user_link.short_description = 'User'

    def ip_address_display(self, obj):
        """Display IP address"""
        if obj.ip_address:
            return format_html('<code>{}</code>', obj.ip_address)
        return '-'
    ip_address_display.short_description = 'IP Address'

    def resolution_status(self, obj):
        """Display resolution information"""
        if obj.status == 'resolved':
            if obj.resolved_by and obj.resolved_at:
                return format_html(
                    '<span style="color: green; font-size: 0.8em;">Resolved by {} on {}</span>',
                    obj.resolved_by.email,
                    obj.resolved_at.strftime('%Y-%m-%d')
                )
        elif obj.status == 'false_positive':
            return format_html('<span style="color: orange; font-size: 0.8em;">False Positive</span>')
        elif obj.status == 'ignored':
            return format_html('<span style="color: gray; font-size: 0.8em;">Ignored</span>')
        else:
            return format_html('<span style="color: red; font-size: 0.8em;">Active</span>')
    resolution_status.short_description = 'Resolution'

    def mark_as_resolved(self, request, queryset):
        """Mark events as resolved"""
        updated = queryset.filter(status='active').update(status=SecurityEvent.Status.RESOLVED)
        self.message_user(request, ngettext(
            '%d security event was successfully marked as resolved.',
            '%d security events were successfully marked as resolved.',
            updated,
        ) % updated)
    mark_as_resolved.short_description = _("Mark selected events as resolved")

    def mark_as_false_positive(self, request, queryset):
        """Mark events as false positive"""
        updated = queryset.filter(status='active').update(status=SecurityEvent.Status.FALSE_POSITIVE)
        self.message_user(request, ngettext(
            '%d security event was successfully marked as false positive.',
            '%d security events were successfully marked as false positive.',
            updated,
        ) % updated)
    mark_as_false_positive.short_description = _("Mark selected events as false positive")

    def mark_as_ignored(self, request, queryset):
        """Mark events as ignored"""
        updated = queryset.filter(status='active').update(status=SecurityEvent.Status.IGNORED)
        self.message_user(request, f"Ignored {updated} security event(s).")
    mark_as_ignored.short_description = "Mark as ignored"

    def export_security_events(self, request, queryset):
        """Export security events to CSV"""
        import csv
        from django.http import HttpResponse

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="security_events.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Event Type', 'Title', 'Severity', 'Status', 'User', 'IP Address',
            'Created At', 'Resolved At'
        ])

        for event in queryset.select_related('user', 'resolved_by'):
            writer.writerow([
                event.event_type,
                event.title,
                event.severity,
                event.status,
                event.user.email if event.user else '',
                event.ip_address or '',
                event.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                event.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if event.resolved_at else ''
            ])

        return response
    export_security_events.short_description = "Export security events to CSV"

    def bulk_resolve_with_note(self, request, queryset):
        """Bulk resolve events with a note"""
        if 'apply' in request.POST:
            note = request.POST.get('resolution_note')
            updated = queryset.filter(status='active').update(
                status=SecurityEvent.Status.RESOLVED,
                resolution_notes=note,
                resolved_at=timezone.now()
            )
            self.message_user(request, f"Resolved {updated} event(s) with note.")
            return

        # Show form
        from django.shortcuts import render
        return render(request, 'admin/bulk_resolve_events.html', {
            'events': queryset
        })
    bulk_resolve_with_note.short_description = "Bulk resolve with note"


@admin.register(SecuritySettings)
class SecuritySettingsAdmin(admin.ModelAdmin):
    list_display = (
        'setting_type_badge', 'name', 'is_enabled_badge',
        'config_summary', 'updated_at'
    )
    list_filter = ('setting_type', 'is_enabled', 'created_at')
    search_fields = ('name', 'description', 'setting_type')
    readonly_fields = ('id', 'created_at', 'updated_at')
    ordering = ('setting_type',)
    actions = [
        'enable_settings', 'disable_settings', 'reset_to_defaults',
        'export_security_settings'
    ]

    fieldsets = (
        (_('Basic Information'), {
            'fields': ('id', 'setting_type', 'name', 'description', 'is_enabled')
        }),
        (_('Configuration'), {
            'fields': ('config',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def setting_type_badge(self, obj):
        """Display setting type with colored badge"""
        type_colors = {
            'rate_limit': 'blue',
            'password_policy': 'green',
            'session_policy': 'orange',
            'encryption': 'purple',
            'audit': 'red'
        }
        color = type_colors.get(obj.setting_type, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_setting_type_display()
        )
    setting_type_badge.short_description = 'Type'

    def is_enabled_badge(self, obj):
        """Display enabled status with badge"""
        if obj.is_enabled:
            return format_html(
                '<span style="background-color: green; color: white; padding: 3px 8px; '
                'border-radius: 4px; font-size: 0.8em;">✓ Enabled</span>'
            )
        return format_html(
            '<span style="background-color: red; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">✗ Disabled</span>'
        )
    is_enabled_badge.short_description = 'Status'

    def config_summary(self, obj):
        """Display a summary of the configuration"""
        if obj.config:
            keys = list(obj.config.keys())
            if len(keys) <= 3:
                summary = ', '.join(keys)
            else:
                summary = ', '.join(keys[:3]) + f' (+{len(keys) - 3} more)'
            return format_html('<span style="font-size: 0.8em; color: #666;">{}</span>', summary)
        return format_html('<span style="color: gray; font-size: 0.8em;">No config</span>')
    config_summary.short_description = 'Config'

    def enable_settings(self, request, queryset):
        """Enable selected security settings"""
        updated = queryset.filter(is_enabled=False).update(is_enabled=True)
        self.message_user(request, f"Enabled {updated} security setting(s).")
    enable_settings.short_description = "Enable settings"

    def disable_settings(self, request, queryset):
        """Disable selected security settings"""
        updated = queryset.filter(is_enabled=True).update(is_enabled=False)
        self.message_user(request, f"Disabled {updated} security setting(s).")
    disable_settings.short_description = "Disable settings"

    def reset_to_defaults(self, request, queryset):
        """Reset settings to defaults"""
        updated = queryset.update(config={})
        self.message_user(request, f"Reset {updated} setting(s) to defaults.")
    reset_to_defaults.short_description = "Reset to defaults"

    def export_security_settings(self, request, queryset):
        """Export security settings to CSV"""
        import csv
        from django.http import HttpResponse

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="security_settings.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Setting Type', 'Name', 'Description', 'Enabled', 'Config', 'Updated At'
        ])

        for setting in queryset:
            writer.writerow([
                setting.setting_type,
                setting.name,
                setting.description or '',
                setting.is_enabled,
                str(setting.config),
                setting.updated_at.strftime('%Y-%m-%d %H:%M:%S')
            ])

        return response
    export_security_settings.short_description = "Export security settings to CSV"


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'key_type_badge', 'user_link', 'key_preview',
        'is_active_badge', 'expires_display', 'last_used_display', 'rate_limit_display'
    )
    list_filter = (
        'key_type', 'is_active', 'created_at', 'expires_at'
    )
    search_fields = (
        'name', 'user__email', 'user__first_name', 'user__last_name', 'key'
    )
    readonly_fields = ('id', 'key', 'created_at', 'updated_at', 'last_used_at')
    ordering = ('-created_at',)
    actions = [
        'activate_keys', 'deactivate_keys', 'regenerate_keys',
        'export_api_keys', 'bulk_update_rate_limits'
    ]

    fieldsets = (
        (_('Basic Information'), {
            'fields': ('id', 'name', 'key_type', 'key', 'user')
        }),
        (_('Configuration'), {
            'fields': ('permissions', 'rate_limit', 'is_active', 'expires_at')
        }),
        (_('Usage'), {
            'fields': ('last_used_at',),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def key_type_badge(self, obj):
        """Display key type with colored badge"""
        type_colors = {
            'service': 'blue',
            'user': 'green',
            'integration': 'orange'
        }
        color = type_colors.get(obj.key_type, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 0.8em;">{}</span>',
            color, obj.get_key_type_display()
        )
    key_type_badge.short_description = 'Type'

    def user_link(self, obj):
        """Link to the user who owns the API key"""
        if obj.user:
            url = reverse('admin:accounts_user_change', args=[obj.user.id])
            return format_html('<a href="{}">{}</a>', url, obj.user.email)
        return '-'
    user_link.short_description = 'User'

    def key_preview(self, obj):
        """Display masked API key"""
        if obj.key:
            masked = obj.key[:8] + '...' + obj.key[-4:] if len(obj.key) > 12 else obj.key
            return format_html('<code title="{}">{}</code>', obj.key, masked)
        return '-'
    key_preview.short_description = 'API Key'

    def is_active_badge(self, obj):
        """Display active status with badge"""
        if not obj.is_active:
            return format_html(
                '<span style="background-color: red; color: white; padding: 3px 8px; '
                'border-radius: 4px; font-size: 0.8em;">✗ Inactive</span>'
            )
        elif obj.is_expired:
            return format_html(
                '<span style="background-color: orange; color: white; padding: 3px 8px; '
                'border-radius: 4px; font-size: 0.8em;">⏰ Expired</span>'
            )
        else:
            return format_html(
                '<span style="background-color: green; color: white; padding: 3px 8px; '
                'border-radius: 4px; font-size: 0.8em;">✓ Active</span>'
            )
    is_active_badge.short_description = 'Status'

    def expires_display(self, obj):
        """Display expiration information"""
        if obj.expires_at:
            if obj.is_expired:
                return format_html(
                    '<span style="color: red; font-size: 0.8em;">Expired {}</span>',
                    obj.expires_at.strftime('%Y-%m-%d')
                )
            else:
                days_remaining = (obj.expires_at - timezone.now()).days
                if days_remaining <= 7:
                    color = 'red' if days_remaining <= 1 else 'orange'
                    return format_html(
                        '<span style="color: {}; font-size: 0.8em;">Expires in {} days</span>',
                        color, days_remaining
                    )
                else:
                    return format_html(
                        '<span style="color: green; font-size: 0.8em;">{}</span>',
                        obj.expires_at.strftime('%Y-%m-%d')
                    )
        return format_html('<span style="color: gray; font-size: 0.8em;">Never</span>')
    expires_display.short_description = 'Expires'

    def last_used_display(self, obj):
        """Display last used information"""
        if obj.last_used_at:
            days_since = (timezone.now() - obj.last_used_at).days
            if days_since == 0:
                return format_html('<span style="color: green; font-size: 0.8em;">Today</span>')
            elif days_since == 1:
                return format_html('<span style="color: blue; font-size: 0.8em;">Yesterday</span>')
            elif days_since <= 7:
                return format_html('<span style="color: orange; font-size: 0.8em;">{} days ago</span>', days_since)
            else:
                return format_html('<span style="color: red; font-size: 0.8em;">{} days ago</span>', days_since)
        return format_html('<span style="color: gray; font-size: 0.8em;">Never</span>')
    last_used_display.short_description = 'Last Used'

    def rate_limit_display(self, obj):
        """Display rate limit information"""
        return format_html('<span style="font-size: 0.8em;">{}/hour</span>', obj.rate_limit)
    rate_limit_display.short_description = 'Rate Limit'

    def activate_keys(self, request, queryset):
        """Activate selected API keys"""
        updated = queryset.filter(is_active=False).update(is_active=True)
        self.message_user(request, f"Activated {updated} API key(s).")
    activate_keys.short_description = "Activate keys"

    def deactivate_keys(self, request, queryset):
        """Deactivate selected API keys"""
        updated = queryset.filter(is_active=True).update(is_active=False)
        self.message_user(request, f"Deactivated {updated} API key(s).")
    deactivate_keys.short_description = "Deactivate keys"

    def regenerate_keys(self, request, queryset):
        """Regenerate selected API keys"""
        for api_key in queryset:
            api_key.generate_key()
            api_key.save()
        self.message_user(request, f"Regenerated {queryset.count()} API key(s).")
    regenerate_keys.short_description = "Regenerate keys"

    def export_api_keys(self, request, queryset):
        """Export API keys to CSV"""
        import csv
        from django.http import HttpResponse

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="api_keys.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Name', 'Type', 'User', 'Key', 'Active', 'Expires At',
            'Last Used', 'Rate Limit', 'Created At'
        ])

        for key in queryset.select_related('user'):
            writer.writerow([
                key.name,
                key.key_type,
                key.user.email if key.user else '',
                key.key,
                key.is_active,
                key.expires_at.strftime('%Y-%m-%d %H:%M:%S') if key.expires_at else '',
                key.last_used_at.strftime('%Y-%m-%d %H:%M:%S') if key.last_used_at else '',
                key.rate_limit,
                key.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])

        return response
    export_api_keys.short_description = "Export API keys to CSV"

    def bulk_update_rate_limits(self, request, queryset):
        """Bulk update rate limits"""
        if 'apply' in request.POST:
            rate_limit = request.POST.get('rate_limit')
            if rate_limit:
                updated = queryset.update(rate_limit=int(rate_limit))
                self.message_user(request, f"Updated rate limit for {updated} API key(s).")
            return

        # Show form
        from django.shortcuts import render
        return render(request, 'admin/bulk_update_rate_limits.html', {
            'api_keys': queryset
        })
    bulk_update_rate_limits.short_description = "Bulk update rate limits"

    def get_readonly_fields(self, request, obj=None):
        if obj:  # Editing existing object
            return self.readonly_fields + ['key']
        return self.readonly_fields
