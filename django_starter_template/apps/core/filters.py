"""
Filters for core app using django-filter
"""
import django_filters
from django.contrib.admin.models import LogEntry


class LogEntryFilter(django_filters.FilterSet):
    """Filter for LogEntry (audit log) model"""
    user = django_filters.CharFilter(field_name='user__username', lookup_expr='icontains')
    user_id = django_filters.NumberFilter(field_name='user__id')
    action_time_after = django_filters.DateTimeFilter(field_name='action_time', lookup_expr='gte')
    action_time_before = django_filters.DateTimeFilter(field_name='action_time', lookup_expr='lte')
    action_flag = django_filters.ChoiceFilter(choices=[
        (1, 'Addition'),
        (2, 'Change'),
        (3, 'Deletion'),
    ])
    content_type = django_filters.CharFilter(field_name='content_type__model', lookup_expr='icontains')
    content_type_id = django_filters.NumberFilter(field_name='content_type__id')
    object_id = django_filters.CharFilter(lookup_expr='icontains')
    object_repr = django_filters.CharFilter(lookup_expr='icontains')
    change_message = django_filters.CharFilter(lookup_expr='icontains')

    class Meta:
        model = LogEntry
        fields = [
            'user', 'user_id', 'action_time_after', 'action_time_before',
            'action_flag', 'content_type', 'content_type_id', 'object_id',
            'object_repr', 'change_message'
        ]