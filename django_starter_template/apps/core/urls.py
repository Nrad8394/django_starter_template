"""
Core routes: health, CSRF, task status, auth.

Nothing domain-specific belongs here. The version this replaces routed
``/my-classes/`` and ``/pending-approvals/`` — a school timetable leaking into
the shared core app of a general-purpose template — and referenced two view
functions (``dashboard_statistics``, ``my_classes``) that did not exist, so
importing this module raised ``AttributeError`` and the whole URLconf failed
to load. Anything resembling a domain endpoint goes in its own app.
"""

from django.urls import include, path

from . import health, views

app_name = "core"

urlpatterns = [
    # --- Probes ---------------------------------------------------------
    # Also mounted at the project root in `django_starter_template/urls.py`
    # so orchestrators can reach them without knowing the API prefix.
    path("health/", health.liveness, name="liveness"),
    path("readyz/", health.readiness, name="readiness"),
    path("version/", health.version, name="version"),
    # --- CSRF -----------------------------------------------------------
    # Only needed if some part of your app uses session authentication (the
    # admin, or an allauth HTML flow). A pure JWT client never calls this.
    path("csrf-token/", views.get_csrf_token, name="csrf_token"),
    # --- Background tasks -----------------------------------------------
    path("tasks/<uuid:task_id>/status/", views.task_status, name="task_status"),
    # --- Authentication --------------------------------------------------
    path("auth/", include("apps.core.auth_urls")),
]
