# Auth app consolidation

The template used to ship two overlapping user apps. It now ships one:
**`apps.accounts`**, providing `AUTH_USER_MODEL = "accounts.User"`.

`apps.authentication` has been deleted.

This document records what was merged and what changed on the way, because
several of the changes alter behaviour and you should know about them before
building on the model.

---

## Why there were two, and why neither worked

`apps.accounts` was the original user app: its migration created `User`,
`UserRole`, `UserProfile`, `UserSession`, `LoginAttempt` and
`UserRoleHistory`.

At some point `User` and `UserRole` were lifted out into a new
`apps.authentication` app and `AUTH_USER_MODEL` was repointed at it — but
`apps/accounts/models.py` was left still referring to `User` and `UserRole` by
bare name, with no definition and no import. Importing the module raised
`NameError`, so `apps.accounts` had to be commented out of `INSTALLED_APPS`,
which is how the template was shipped.

The result: the larger, more complete user app could not be enabled, and the
smaller one that replaced it had its own problems (below). Merging back into
`accounts` restores the full feature set and makes the app importable.

---

## What changed in the `User` model

### Primary key: institutional string → UUID

Was:

```python
id = models.CharField(
    primary_key=True, max_length=50, editable=True, db_column="user_id",
    help_text="Institutional user ID used as primary key, e.g. SIG00125",
)
```

Two problems. It hard-codes one organisation's numbering scheme into every
project generated from the template. And it has **no default**, while
`create_user()` never set it — so the first user was created with `id=""` and
the second violated the unique constraint. The model could not be used.

Now a UUID, inherited from `TimestampedModel`, consistent with `BaseModel`
everywhere else in the project.

**If you want human-readable user IDs**, add `PublicIDMixin`
(`apps/core/mixins.py`) rather than reintroducing a string primary key:

```python
class User(PublicIDMixin, AbstractUser, TimestampedModel, SoftDeleteMixin):
    PUBLIC_ID_PREFIX = "USR"
```

That gives you `USR-8K2X7P9Q4Z` for display and keeps a stable UUID as the
foreign-key target.

### `role` is now nullable

Was `null=False, blank=False` with `on_delete=PROTECT`. That makes the project
impossible to bootstrap: `createsuperuser` has no way to supply a role, and no
`UserRole` row can exist before someone creates one. Chicken and egg, with a
`NOT NULL` constraint in the middle.

Now nullable. **Enforce a role in the application layer** — a serializer
validator, or a signal on user creation — where you can return a useful
message. A database constraint that deadlocks `manage.py createsuperuser` is
the wrong place for that rule.

### `username` is optional

`AbstractUser` makes it required and unique. With `USERNAME_FIELD = "email"`,
a second required unique field is just another way for registration to fail.
Kept as a nullable field rather than removed, so third-party packages that
read `user.username` keep working.

### `UserManager` now filters soft-deleted users

The previous manager was a plain `BaseUserManager`. Because a model has only
one `_default_manager`, declaring it silently overrode
`SoftDeleteMixin.objects` — so soft-deleted users came back in every query,
**including the authentication backend's `get_by_natural_key()` lookup.** A
"deleted" user could still sign in.

`UserManager` is now built from `SoftDeleteQuerySet` and filters `alive()`.
`User.all_objects` still returns everyone, so the admin and the restore
endpoints work. `Meta.base_manager_name = "all_objects"` keeps Django's
related-object traversal correct.

### Biometric fields removed

The old `accounts` migration carried `embedding_vector`, `embedding_hash`,
`face_quality_score`, `face_confidence_score`, `face_enrolled_at`,
`face_enrollment_verified` and `face_last_used` — a facial-recognition
enrolment system on the user model.

Removed, for two reasons. It is another product's domain leaking into a
general-purpose template; and face embeddings are special-category personal
data under GDPR Article 9, with separate statutory regimes in several US
states. Shipping those columns switched on by default makes every project
generated from this template handle biometric data whether or not it meant
to.

Only three code sites referenced them (against 15–48 for every field that was
kept), all in a `ProfileCompletionService` that has been rewritten.

If you need biometric enrolment, build it as its own app behind an explicit
consent flow.

---

## Fields that were kept

Everything with real usage across the codebase:

| Group | Fields |
|---|---|
| Identity | `email` (unique, `USERNAME_FIELD`), `username` (optional), `first_name`, `last_name` |
| State | `is_active`, `is_staff`, `is_superuser`, `is_verified`, `is_approved`, `terms_accepted` |
| Login security | `failed_login_attempts`, `account_locked_until`, `last_login_ip` |
| Password lifecycle | `must_change_password`, `password_changed_at` |
| MFA | `otp_device`, `backup_codes` |
| Profile | `profile_image`, `profile_complete`, `profile_completed_at` |
| Authorization | `role` (nullable FK to `UserRole`) |
| Inherited | `id` (UUID), `created_at`, `updated_at`, `is_deleted`, `deleted_at`, `deleted_by` |

---

## Migrations

Regenerated from scratch as `0001_initial` + `0002_add_otp_device`. The
template has no production data, so a clean pair is better than a patch chain
describing a model that no longer exists.

**The two-migration split is load-bearing — do not squash it.**
`django_otp`'s `TOTPDevice` has its own foreign key to `AUTH_USER_MODEL`, so
declaring `User.otp_device` in the initial migration makes `accounts.0001` and
`otp_totp.0001` depend on each other. Django refuses the whole graph with
`CircularDependencyError` and *nothing* migrates. Creating the `User` table
first and adding the field in `0002` is the documented way out.

---

## Other things fixed while merging

**`apps/core/services/` deleted.** The project had both `apps/core/services.py`
and an `apps/core/services/` package. In Python the package wins, so
`services.py` was unreachable by normal import — which is why the package's
`__init__.py` contained an `importlib.util.spec_from_file_location` shim to
load the shadowed module by file path. The package held the facial-recognition
`ProfileCompletionService`; deleting it removed the biometric code and the
name collision together. All `from apps.core.services import ...` statements
now resolve normally.

**Privilege escalation in `ProfileCompletionService`.** It applied request
data to the user model with:

```python
for key, value in profile_data.items():
    if hasattr(user, key) and value is not None:
        setattr(user, key, value)
```

`hasattr` is true for every field on the model, so a profile update could
include `is_superuser`, `is_staff`, `is_approved`, `role_id` or `password` and
have it applied. There is now an explicit `EDITABLE_FIELDS` allowlist, and
ignored keys are logged rather than silently dropped.

**`UserAdmin` referenced `user_id`.** That was the old primary key's
`db_column`. With the UUID PK it raised `admin.E108` at system-check time.

---

## Checklist if you are renaming the app

`AUTH_USER_MODEL` is effectively immutable once migrations exist. Do this
before your first `migrate`:

1. Rename the directory `apps/accounts/`.
2. Update `label` in `apps/<new>/apps.py` — this is the string
   `AUTH_USER_MODEL` refers to.
3. Update `AUTH_USER_MODEL` in `settingsConfig/core/django_configs.py`.
4. Update `LOCAL_APPS` in `settingsConfig/core/apps.py`.
5. Update the jazzmin references in `settingsConfig/admin/jazzmin.py`.
6. Delete `apps/<new>/migrations/000*.py` and re-run `makemigrations`.

Everything else in the project reaches the user model through
`settings.AUTH_USER_MODEL` or `get_user_model()`, so no other file needs to
change.
