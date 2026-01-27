from django_filters import rest_framework as filters
from django.utils.translation import gettext_lazy as _

from .models import User


class UserFilter(filters.FilterSet):
    """Custom filterset for User views.
  
    We  provide a `role` filter that maps to role.name for easier
    filtering by role name.
    """

    role = filters.CharFilter(field_name="role__name", lookup_expr="iexact")

    class Meta:
        model = User
        # Only include model fields here (no double-underscore lookups).
        fields = ["is_active", "role__name", "date_joined"]
