# Django Starter Template

A Django + DRF backend with the parts every project rebuilds already built:
JWT authentication, a consistent API error contract, soft delete, bulk
CRUD/import/export, Celery, S3-compatible storage, OpenAPI, Docker, and CI.

It is opinionated on purpose. Where a decision could go either way, the
reasoning is in the code next to the decision, and the cross-cutting ones are
collected in [`../PATTERNS.md`](../PATTERNS.md).

---

## Quick start

```bash
cd django_starter_template
cp env.example .env

# Docker (brings up Postgres, Redis, the API, a Celery worker and beat)
docker compose up --build
docker compose exec api python manage.py migrate
docker compose exec api python manage.py createsuperuser

# …or locally, with Postgres and Redis already running
uv sync --all-extras
python manage.py migrate
python manage.py runserver
```

| URL | What |
|---|---|
| `http://localhost:8000/api/v1/` | API root |
| `http://localhost:8000/api/v1/schema/swagger-ui/` | Interactive docs |
| `http://localhost:8000/admin/` | Django admin |
| `http://localhost:8000/health/` | Liveness probe |
| `http://localhost:8000/readyz/` | Readiness probe |

---

## Renaming the project

The Python package is `django_starter_template`. To rename it:

```bash
NEW=my_project
git mv django_starter_template/django_starter_template "django_starter_template/$NEW"
grep -rl 'django_starter_template' --include='*.py' --include='*.toml' \
     --include='*.yml' --include='*.cfg' --include='Dockerfile' . \
  | xargs sed -i "s/django_starter_template/$NEW/g"
```

Then check `pyproject.toml` (`[project].name`, `known-first-party`,
`DJANGO_SETTINGS_MODULE`), the `Dockerfile` (the gunicorn target in the
entrypoint) and `docker-compose.yml` (the Celery `-A` argument).

---

## Decide these before writing any code

**1. The app name behind `AUTH_USER_MODEL`.** It is `accounts.User`.
`AUTH_USER_MODEL` is effectively immutable once migrations exist — changing it
later means squashing everything and rebuilding the database, because Django
offers no supported path. If you want a different app name, rename it now;
`docs/AUTH_APP_CONSOLIDATION.md` has the six-step checklist.

**2. Primary key type.** `BaseModel` and `User` use a UUID.
`apps/core/models.py` explains the trade-off and how to opt back into
integers. For human-readable identifiers, add `PublicIDMixin` rather than
changing the primary key.

**3. Whether `role` should be required.** It is nullable, deliberately — a
required role FK makes `createsuperuser` impossible, since no role can exist
before the first user creates one. Enforce it in a serializer or a signal
instead, where you can return a useful message.

---

## Layout

```
django_starter_template/
├── django_starter_template/       # project package
│   ├── settings.py                # profile selector — read its docstring
│   ├── settingsConfig/
│   │   ├── env.py                 # typed env readers
│   │   ├── base.py                # composes the feature modules
│   │   ├── development.py  test.py  production.py
│   │   ├── api/ auth/ core/ services/ storage/ logging/
│   ├── celery_app.py  urls.py  wsgi.py  asgi.py
├── apps/
│   ├── core/                      # the reusable half of this template
│   │   ├── models.py              # BaseModel, soft delete, SingletonModel
│   │   ├── mixins.py              # PublicIDMixin
│   │   ├── viewsets.py            # BaseModelViewSet — bulk, import/export
│   │   ├── exceptions.py          # the API error contract
│   │   ├── permissions.py  pagination.py  schema.py
│   │   ├── health.py              # liveness / readiness
│   │   ├── middleware.py  context.py
│   ├── accounts/                  # AUTH_USER_MODEL, roles, profiles, sessions
│   ├── notifications/             # in-app + email notifications (disabled)
│   └── security/                  # audit log, rate limiting (disabled)
├── Dockerfile  docker-compose.yml  .dockerignore
└── pyproject.toml  env.example
```

---

## The parts worth knowing

### One error shape, always

Every non-2xx response looks like this — validation failure, permission
denial, 404, throttle, or crash:

```json
{
  "error": {
    "type": "validation_error",
    "message": "Please correct the errors below.",
    "detail": [
      {"field": "email", "code": "required", "message": "This field is required."},
      {"field": "items.1.qty", "code": "min_value", "message": "Must be positive."}
    ],
    "request_id": "3f2a9c14-8b7d-4e21-9a5f-1c6e0b3d7a48"
  }
}
```

`type` is a stable slug to branch on. `message` is a sentence you can put in a
toast. `detail` is flat, with dotted paths for nested serializers, so a client
maps errors onto form fields without walking a tree. `request_id` is echoed in
the `X-Request-ID` header and attached to every log line for that request.

This is the highest-leverage thing in the template. `apps/core/exceptions.py`
explains what happens without it — including the real frontend that ended up
regex-matching Python's `ErrorDetail(string='...')` repr out of response
bodies.

### `BaseModelViewSet`

```python
class ProductViewSet(BaseModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    search_fields = ["name", "sku"]
    ordering_fields = ["name", "price", "created_at"]
    export_fields = ["sku", "name", "price", "created_at"]
```

That gets you CRUD plus:

| Endpoint | |
|---|---|
| `POST /bulk_create/` | many objects, one transaction |
| `POST /bulk_update/` | `{"updates": [{"id", "data"}]}`, each validated |
| `POST /bulk_delete/` | soft delete where supported, partial-success reporting |
| `POST /bulk_restore/` | undelete |
| `POST /{id}/restore/` `POST /{id}/hard_delete/` | single-object trash actions |
| `GET /bulk_export/` | CSV/XLSX, restricted to `export_fields` |
| `POST /bulk_import/` | CSV/XLSX, all-or-nothing |
| `GET /bulk_import_template/` | a spreadsheet matching the create serializer |
| `GET /statistics/` | counts, extensible via `get_extra_statistics()` |

List views accept `?is_deleted=true` (trash) and `?show_deleted=true` (both).

Three deliberate restrictions, each explained in the module docstring: bulk
update always goes through the serializer, export requires an explicit field
allowlist, and export is row-capped.

### Soft delete that works

`obj.delete()` marks; `obj.hard_delete()` removes. `Model.objects` hides
deleted rows, `Model.all_objects` does not, and `Meta.base_manager_name`
points at the latter so Django's own related-object traversals keep working.
Getting any one of those three wrong produces a subtly broken abstraction —
`apps/core/models.py` spells out which.

### Permissions

Default is deny: `IsAuthenticated` + `FullDjangoModelPermissions`, which —
unlike DRF's stock `DjangoModelPermissions` — also requires `view_<model>` for
reads. A new viewset is locked until someone grants access.

Object-level permission classes only run on detail routes. They do **not**
filter list responses; scope `get_queryset()` too. `apps/core/permissions.py`
has the details.

---

## Configuration

`DJANGO_SETTINGS_MODULE` always points at `<project>.settings`. The profile is
chosen by `DJANGO_ENV` (`development` | `test` | `production`).

Every setting is documented in `env.example`. The typed readers in
`settingsConfig/env.py` (`get_bool`, `get_int`, `get_list`) exist because
`cast=bool` on an environment variable is a trap — `bool("False")` is `True`.

---

## Testing

```bash
pytest                      # everything
pytest -n auto              # parallel
pytest -m "not slow"        # skip slow tests
pytest --cov --cov-report=html
```

`--reuse-db` is on by default; add `--create-db` after a schema change.
Warnings are errors, so a deprecation gets fixed while it is still a warning.

---

## Deployment notes

- **Migrations are not run by the entrypoint.** With more than one replica,
  every container racing `migrate` on start is a lock-contention and
  half-applied-schema problem. Run it as a one-shot job in your pipeline.
  `RUN_MIGRATIONS_ON_START=true` exists for single-instance deployments.
- **Static files are collected at build time**, so the runtime image is
  immutable and starts without a database.
- **`check --deploy` runs in CI against the production profile.** It is the
  cheapest possible catch for a security setting that regressed.
- **HSTS is hard to undo.** `SECURE_HSTS_SECONDS` starts at 0; raise it in
  steps once every subdomain is HTTPS-only.

---

## What is deliberately absent

- **A thread-local "current user".** `BaseModelViewSet` passes the user to
  `serializer.save()` explicitly. The middleware exists
  (`CurrentUserMiddleware`) but is off — it is empty in Celery tasks and
  management commands, which is how audit columns quietly end up NULL.
- **Role constants.** No `IsSupervisorOrAbove`. Use Django's model
  permissions, which an administrator can change without a deploy; `HasRole`
  is there for the cases model permissions genuinely cannot express.
- **A coverage gate.** It mostly teaches people to write tests that execute
  lines without asserting anything.
