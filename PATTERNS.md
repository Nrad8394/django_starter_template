# Patterns & Decisions

> **This file is mirrored in both templates.** It documents decisions that
> span the pair (`django_starter_template` and `Fronted_Web_Template`), because
> several of them — the error contract, the pagination shape, the bulk
> endpoints — are contracts *between* them and only make sense together.
> Edit both copies, or they drift.

A record of what these templates do, why, and — where a pattern was harvested
from a real project — what was changed on the way in and what was left behind.

Every entry has a verdict:

| | |
|---|---|
| **Adopted** | Taken as-is. It earned its place. |
| **Adopted, corrected** | Good idea, broken or unsafe implementation. Reworked. |
| **Rejected** | Looked reasonable; does not survive scrutiny. Not in the template, and here so nobody re-adds it. |
| **Deferred** | Worth having, not yet built. |

The source for this round was a production property-management stack
(Django + DRF backend, Next.js frontend) built from earlier versions of these
templates. It is referenced below as "the source project". Its mistakes are
recorded without apology because they are the useful part: a template that
only records what went right teaches nothing about why the rules exist.

---

## Contents

- [1. The API error contract](#1-the-api-error-contract) — the big one
- [2. Runtime vs build-time configuration](#2-runtime-vs-build-time-configuration)
- [3. Relative endpoints](#3-relative-endpoints)
- [4. Token storage](#4-token-storage)
- [5. The refresh mutex](#5-the-refresh-mutex)
- [6. Soft delete](#6-soft-delete)
- [7. Bulk update and mass assignment](#7-bulk-update-and-mass-assignment)
- [8. Export allowlists and row caps](#8-export-allowlists-and-row-caps)
- [9. Settings profile selection](#9-settings-profile-selection)
- [10. Environment variable coercion](#10-environment-variable-coercion)
- [11. Audit fields: explicit vs thread-local](#11-audit-fields-explicit-vs-thread-local)
- [12. Permissions: Django's, not yours](#12-permissions-djangos-not-yours)
- [13. Public IDs](#13-public-ids)
- [14. Liveness vs readiness](#14-liveness-vs-readiness)
- [15. Import: all-or-nothing](#15-import-all-or-nothing)
- [16. Smaller calls](#16-smaller-calls)
- [17. Deferred](#17-deferred)
- [18. Domain leakage found and removed](#18-domain-leakage-found-and-removed)
- [19. One user app](#19-one-user-app)
- [20. The entity layer](#20-the-entity-layer)

---

## 1. The API error contract

**Verdict: added. Neither the templates nor the source project had one.**

Both projects used DRF's stock exception handler, which returns whatever shape
the exception happens to carry:

```
ValidationError    →  {"email": ["This field is required."]}
ValidationError    →  {"non_field_errors": ["Passwords do not match."]}
PermissionDenied   →  {"detail": "You do not have permission…"}
Http404            →  {"detail": "Not found."}
IntegrityError     →  an HTML 500 page
nested serializer  →  {"items": [{}, {"qty": ["Must be positive."]}]}
```

Six shapes and no way for a client to know which it got. What the frontend
grew in response is the instructive part — a 150-line handler that walks
unknown object graphs, and at its centre:

```ts
const responseText = JSON.stringify(data);
const errorDetailPattern = /ErrorDetail\(string='([^']+)',\s*code='([^']+)'\)/g;
const matches = Array.from(responseText.matchAll(errorDetailPattern));
```

TypeScript regex-matching the `repr()` of a Python object out of a JSON body.

It is easy to read that as a frontend failure. It is not. The frontend was
handed six contracts and asked to guess; the regex is what guessing looks like
after a year. The cause is that the API never committed to a response shape,
and every new client — mobile app, CLI, partner integration — would have paid
the same cost again.

**The template now guarantees one envelope for every non-2xx response:**

```json
{
  "error": {
    "type": "validation_error",
    "message": "Please correct the errors below.",
    "detail": [
      {"field": "email", "code": "required", "message": "This field is required."},
      {"field": "items.1.qty", "code": "min_value", "message": "Must be positive."}
    ],
    "request_id": "3f2a9c14-…"
  }
}
```

- `type` — stable slug. Branch on this, never on prose.
- `message` — one sentence, safe for a toast.
- `detail` — **flat**, with dotted paths for nested serializers. Deliberate:
  dotted paths are already react-hook-form's field-name format, so errors map
  onto inputs with no translation layer. The flattening happens once, on the
  server, instead of in every client.
- `request_id` — echoed in `X-Request-ID` and attached to every log line, so a
  user's screenshot leads to the exact request.

The handler also converts Django-level exceptions DRF ignores. `IntegrityError`
from a unique-constraint race is a routine client error, not a 500 and a
pager alert.

The whole client-side handler is now:

```ts
const { message, fieldErrors } = normalizeError(err);
```

`lib/api/errors.ts` keeps a small fallback for legacy shapes. It is a safety
net; extending it is a signal to fix the API instead.

> **Alternative considered:** RFC 9457 `application/problem+json`. The mapping
> is mechanical (`type` → a URI, `message` → `title`). Rejected because
> RFC 9457's URI-valued `type` is almost never dereferenced in practice and
> adds ceremony without adding information. If you need the standard for an
> external contract, the swap is contained to one module.

**Files:** `apps/core/exceptions.py`, `apps/core/schema.py`,
`lib/api/errors.ts`

---

## 2. Runtime vs build-time configuration

**Verdict: adopted from the source project.** One of its genuinely good ideas.

Next.js inlines `process.env.NEXT_PUBLIC_*` at build time. In a Docker
workflow that means one image per environment: you cannot promote a tested
artefact from staging to production, and changing an API URL is a rebuild.

The fix — `docker-entrypoint.sh` writes `public/env-config.js` at container
start, the layout loads it `beforeInteractive`, `lib/env.ts` reads
`window.__ENV__` with a `process.env` fallback — is carried over intact.

The subtle part is carried over too, because it is what makes the mechanism
work at all: **the accessors must be functions, not module constants.** A
`const` captures its value on first import, which can precede `env-config.js`,
freezing the build-time fallback forever. Correct in development, pointed at
`localhost:8000` in production, silently.

`normalizeApiUrl()` is also kept. It strips a trailing dot from the hostname —
`api.example.com.` resolves identically but is a *different origin* to the
browser, so same-origin requests become cross-origin and fail as an
inscrutable CORS error. That is a bug worth inheriting the fix for.

**Files:** `lib/env.ts`, `docker-entrypoint.sh`, `app/layout.tsx`

---

## 3. Relative endpoints

**Verdict: corrected.** The source project's approach caused a bug it then
worked around rather than fixed.

Its endpoint registry built absolute URLs at module scope:

```ts
static get Login() { return `${Endpoints.BaseUrl}/api/v1/auth/login/`; }
```

Some call sites captured those at module init — before `window.__ENV__`
existed — freezing the host. The response was an interceptor that took the URL
apart again on every single request:

```ts
if (config.url && /^https?:\/\//i.test(config.url)) {
  const parsed = new URL(config.url);
  if (parsed.pathname.startsWith('/api/')) {
    config.url = `${parsed.pathname}${parsed.search}${parsed.hash}`;
  }
}
```

Building a URL and then dismantling it is the symptom. The cause is building
it too early.

**The template stores relative paths.** `/api/v1/auth/login/`. Axios's
`baseURL` — re-read per request in the request interceptor — supplies the
host. Axios ignores `baseURL` for absolute URLs, so relative paths are also
what makes `baseURL` function at all. The interceptor hack disappears.
`absoluteUrl()` exists for the rare case that genuinely needs a full URL, and
is called at the point of use.

**Files:** `lib/api/endpoints.ts`, `lib/api/client.ts`

---

## 4. Token storage

**Verdict: changed.** The old template used `localStorage`; the source project
used a JS-readable cookie. Neither is meaningfully better than the other.

| | Readable by injected script | Survives tab close |
|---|---|---|
| `localStorage` | yes | yes |
| `js-cookie` (no `HttpOnly`) | yes | yes |
| **In-memory + HttpOnly refresh cookie** | **no** | **no** |

The middle row is the one worth naming, because it reads as the secure option
and is not: `document.cookie` is as reachable from injected script as
`localStorage` is. "Cookie" and "HttpOnly cookie" get conflated.

**The template uses an in-memory access token and an `HttpOnly` refresh
cookie.**

What that does *not* buy you: XSS can still act as the user by calling your
API. What it does buy: the attacker cannot take the credential away. That is
the difference between a session ending when the tab closes and a token that
works from someone else's machine next week.

The cost, stated plainly because it is real: a page reload loses the access
token, so the app calls `/token/refresh/` on mount. One request, one brief
loading state. `PERSIST_REFRESH_TOKEN` exists for backends that cannot set an
HttpOnly cookie — explicitly, with the trade-off documented at the flag,
rather than by default.

**Files:** `lib/auth/token-store.ts`, `lib/auth/auth-context.tsx`

---

## 5. The refresh mutex

**Verdict: adopted from the source project.** The old template lacked it and
was broken under any real load.

The old interceptor called refresh on every 401 independently. Ten concurrent
requests against an expired token fired ten refresh calls. With refresh-token
rotation enabled — the *correct* server setting, since it turns token theft
into a detectable event — the first call rotates and blacklists, and the other
nine present a dead token. Nine fail; the user is logged out at random,
intermittently, under load only.

A single shared promise fixes it. Also carried over: a separate axios instance
for the refresh call, so a 401 from the refresh endpoint cannot re-enter the
refresh interceptor. The source project instead string-matched the URL inside
the interceptor — which works until someone renames the route.

Three further bugs in the old template's interceptor, fixed:

1. `await localStorage.getItem(...)` — `localStorage` is synchronous. Pasted
   from React Native's `AsyncStorage`.
2. **`config.headers = {}` in the no-token branch.** This replaced the entire
   header object, destroying `Content-Type` on every unauthenticated request,
   so POSTs went out untyped and the server rejected them. Never assign to
   `config.headers`; set keys on it.
3. No `_retried` flag, so a server returning 401 for a valid token looped
   forever.

**Files:** `lib/api/client.ts`

---

## 6. Soft delete

**Verdict: adopted from the source project, hardened.** The old template's
version did not work.

It shipped `is_deleted` / `deleted_at` fields, no manager, and the `delete()`
override **commented out** — so `obj.delete()` hard-deleted and every query
returned deleted rows. An abstraction that is worse than not having one,
because callers believe it.

Three things must line up:

1. `delete()` overridden on the instance, or `obj.delete()` hard-deletes.
2. `objects` filters deleted rows, or every list view leaks them.
3. **`Meta.base_manager_name` points at a manager that does *not* filter.**

Point 3 is the one both projects missed. Django uses `_base_manager` for
related-object descriptors and cascade collection. If it filters, then
`invoice.customer` raises `DoesNotExist` when the customer is soft-deleted,
and a real delete silently misses rows. Django's own docs say `_base_manager`
must not filter.

Also corrected: the source project's `all_objects = models.Manager()` returns
a bare QuerySet, so `all_objects.dead()` does not exist. Built
`from_queryset` instead.

Documented rather than solved: **unique constraints still see soft-deleted
rows.** A user who "deletes" an account cannot re-register with the same
email. The template shows the partial-unique-index fix; it cannot apply it
generically because which columns need it is a domain question.

**Files:** `apps/core/models.py`

---

## 7. Bulk update and mass assignment

**Verdict: removed a fast path that was a vulnerability.**

The source project's `bulk_update` accepted two shapes. The second:

```python
ids  = request.data.get("ids", [])
data = request.data.get("data", {})
count = queryset.update(**data)      # ← every field the caller names
```

`QuerySet.update()` writes columns straight to SQL. No serializer validation,
no `clean()`, no signals, no `auto_now`, no `updated_by` — and **no
restriction on which columns the caller may name.** A client could set any
field on any row it could list: a price, `is_deleted`, a foreign key pointing
at another tenant's record. The queryset was permission-scoped, so this was
not wide open; it was still arbitrary column assignment on rows the caller
could see, driven by client-supplied key names. Mass assignment with a
convenience API's face on.

**The template supports only `{"updates": [{"id", "data"}]}`**, each entry
validated by the resource serializer, all-or-nothing, with duplicate ids
rejected (two updates to one row in one request have an order-dependent
outcome). Targets are resolved through the *filtered* queryset, so a caller
can only touch rows it can already see.

If you need genuine bulk-set performance, write a narrow endpoint that names
the one field it changes: `POST /orders/mark_shipped/` taking only `ids`.

**Files:** `apps/core/viewsets.py`, `apps/core/bulk_serializers.py`

---

## 8. Export allowlists and row caps

**Verdict: two corrections to an otherwise good feature.**

The source project's `bulk_export` defaulted to every concrete model field:

```python
fields = [f.name for f in model._meta.fields]
```

So every column added to a model later — internal flags, token hashes,
soft-delete bookkeeping — silently became downloadable by any user who could
list the resource. Nobody decides to expose those; they arrive.

It also streamed an unbounded queryset into an in-memory `openpyxl` workbook.
On a large table that is an OOM kill of the worker.

**The template requires an explicit `export_fields` allowlist** (empty
disables export) and caps rows at `max_export_rows`. When it truncates it says
so in `X-Export-Truncated` — silent truncation reads as a complete export, and
people reconcile against it.

**Files:** `apps/core/viewsets.py`

---

## 9. Settings profile selection

**Verdict: corrected. The old template could not select production settings at
all.**

```python
settings_module = os.environ.get('DJANGO_SETTINGS_MODULE', '…development')
if settings_module == '…settingsConfig.production':
    from .settingsConfig.production import *
```

This can only ever reach the `else`. If `DJANGO_SETTINGS_MODULE` points at
`settingsConfig.production`, Django imports that module directly and this file
never runs. If it points at `…settings` — the only case where this file *does*
run — the comparison is false. **A project deployed with this would run
development settings in production**: `DEBUG=True`, permissive CORS, the
browsable API, and the insecure fallback `SECRET_KEY`. Silently.

Fixed with a separate `DJANGO_ENV` variable, validated against a known set so
a typo raises at startup instead of falling back.

**Files:** `django_starter_template/settings.py`

---

## 10. Environment variable coercion

**Verdict: corrected.**

```python
DEBUG = get_env("DEBUG", default=True, cast=lambda v: str(v).lower() in ("true","1"))
```

Correct where it was used carefully, but the underlying `get_env` applied
`cast` to defaults as well as environment values, and invited `cast=bool` —
which is a trap: `bool("False")` is `True`, so `DEBUG=False` in a `.env` file
turns debug *on*.

The template adds `get_bool` / `get_int` / `get_list`, raises
`ImproperlyConfigured` (which Django reports cleanly) rather than bare
`Exception`, never casts a default, and **rejects unrecognised booleans**.
`DEBUG=ture` should not ship a debug build.

`get_list` drops blank entries: `"a,,b,"` → `["a", "b"]`, not
`["a", "", "b", ""]` — a classic source of an empty hostname in
`ALLOWED_HOSTS`.

**Files:** `settingsConfig/env.py`

---

## 11. Audit fields: explicit vs thread-local

**Verdict: rejected as the default; kept as an opt-in.**

The tempting pattern is middleware storing the request user in a thread-local
so `Model.save()` can populate `created_by` invisibly. Both projects had it
half-wired.

Three problems:

- **It is empty outside a request.** Celery tasks, management commands and
  data migrations have no request, so the field lands as NULL. You find out
  during an audit.
- **It is not async-safe** when implemented with `threading.local()` — under
  ASGI one thread interleaves many requests, so request A reads what request B
  wrote. The failure only appears under concurrency, only in production, and
  produces plausible-looking wrong data rather than an error.
- **It hides the data flow**, which makes it hard to test.

The template's default is explicit: `BaseModelViewSet.perform_create()` passes
the user to `serializer.save()`. Visible, testable, identical inside and
outside a request.

`CurrentUserMiddleware` still ships, disabled, for projects with model-layer
writes that genuinely cannot receive a user — implemented with `contextvars`,
not `threading.local()`, with the caveats at the class.

**Files:** `apps/core/viewsets.py`, `apps/core/middleware.py`,
`apps/core/context.py`

---

## 12. Permissions: Django's, not yours

**Verdict: rejected the role-constant approach.**

The old template shipped `IsSupervisorOrAbove`, `IsStaffMember`,
`CanManageIncidents` — each calling properties like `user.is_supervisor_or_above`
that must exist on the user model. Two problems: they encode one org chart
into a general-purpose template, and they break at import time on any project
whose user model lacks the property.

More fundamentally, a hardcoded role check is **code**. Changing who can do
what means a deploy. Django's model permissions are **data** an administrator
can grant at runtime.

The template defaults to `IsAuthenticated` + `FullDjangoModelPermissions` —
stricter than DRF's stock class, which deliberately leaves `GET` unguarded and
so makes every model listable by any authenticated user unless each view
remembers otherwise. Deny-by-default fails closed: forget to configure a view
and you get a 403 in development, noticed immediately.

`HasRole` exists for what model permissions cannot express — action endpoints
that are not CRUD on one model — and names no roles itself.

Documented prominently because it is the most common way a "secured" API
leaks: **object-level permissions only run on detail routes.** They do not
filter list responses. Scope `get_queryset()` as well.

**Files:** `apps/core/permissions.py`, `settingsConfig/api/rest.py`

---

## 13. Public IDs

**Verdict: adopted from the source project, with one bug fixed.**

Crockford Base32 (no I, L, O, U — the characters people mistype reading an ID
off a screen) short identifiers alongside the UUID primary key. UUIDs are
unusable in the physical world: nobody reads
`f47ac10b-58cc-4372-a567-0e02b2c3d479` down a phone line or prints it on an
invoice. `INV-8K2X7P9Q4Z` survives both.

Fixed: `display_id` hardcoded a 2-character prefix (`public_id[:2]`), so a
3-character prefix rendered as `IN-V8K2X7P9Q4Z`. Now uses
`len(PUBLIC_ID_PREFIX)`.

Changed: retry attempts reduced from 200 to 5. Two hundred collisions means
the ID space is far too small for the table, and the useful response is a
clear error telling you to raise `PUBLIC_ID_LENGTH` — not 195 more attempts.
Collision math is in the docstring.

Kept: the unique constraint is the source of truth, with retry on
`IntegrityError` inside a savepoint. A prior `exists()` check is racy, and
without the nested `atomic()` a failed insert poisons the enclosing
transaction.

**Files:** `apps/core/mixins.py`

---

## 14. Liveness vs readiness

**Verdict: added.** Both projects had a single health endpoint.

They are different questions and conflating them causes outages.

A liveness probe that checks the database will fail during a brief database
blip. The orchestrator concludes the container is broken and kills it. The
replacement fails the same check. A thirty-second database hiccup becomes a
full outage with a restart storm on top.

- `/health/` — liveness. Touches nothing external. Answers "should you restart
  me", and the answer is almost never yes because a dependency is slow.
- `/readyz/` — readiness. Checks database and cache. Failing removes the
  instance from the load balancer without killing it, so it rejoins when the
  dependency recovers.

Both are terse on purpose: a health endpoint reporting library versions is
free reconnaissance. Failure reasons go to the logs, not the response.

The cache check round-trips rather than only writing — several backends accept
a write and discard it when unhealthy, so a write-only check reports green on
a broken cache.

**Files:** `apps/core/health.py`

---

## 15. Import: all-or-nothing

**Verdict: changed the source project's behaviour.**

Its `bulk_import` opened one transaction, validated row by row inside it, and
returned per-row errors — while committing the rows that passed. A spreadsheet
with one bad row left the database in a state nobody asked for, with no
obvious way to resume: re-uploading the corrected file re-imports the good
rows too.

The template validates every row first and writes only if all pass. A
rejected upload with a list of row numbers is easier to reason about and
trivially retryable.

Also removed: a post-save loop that re-checked `null=False` on every model
field, which patched around serializers that were not validating properly
rather than fixing them.

**Files:** `apps/core/viewsets.py`

---

## 16. Smaller calls

**Pagination.** Three near-identical classes each with a copy-pasted
`get_paginated_response`. Three copies of a method that must stay
byte-identical to keep the API contract stable is three chances to break it.
Now one base plus page-size subclasses, with
`get_paginated_response_schema()` so the OpenAPI spec is honest about the
extra keys. `StandardCursorPagination` added for large tables, with the
trade-off (no page numbers, no total count) stated.

**`react-query` hook factory.** Adopted from the source project, corrected: it
called `createApiService(url)()` *inside* component bodies, rebuilding the
closure on every render. `createResource()` is a plain function for module
scope. Cache keys made structured (`[url, 'list', params]`) so prefix
invalidation works.

**`useState` mutations use PATCH, not PUT.** PUT is a full replacement — any
field the form omits is cleared. Most "the form wiped my other fields" reports
are a PUT that should have been a PATCH.

**`_flatten` handles `ErrorDetail` correctly.** It is a `str` subclass;
`str()` yields the message, never the `repr()`. Converting once on the server
is what stops the repr reaching the wire — the root cause of §1's regex.

**`get_extra_actions` override removed.** The source project overrode it to
walk the MRO collecting `@action` methods. DRF's implementation already uses
`getmembers()`, which includes inherited members. The override was redundant
and risked double-registration.

**Query parameter aliases reduced.** The source project accepted `is_deleted`,
`ondelete` *and* `show_deleted` for one concept. Three spellings is three
things to keep working. Now two, each meaning something distinct.

**Middleware ordering documented with reasons.** Notably: `CorsMiddleware`
before `CommonMiddleware`, because `CommonMiddleware` issues `APPEND_SLASH`
redirects and a redirect without CORS headers fails preflight — presenting as
an inscrutable "CORS error" on a request that was only missing a trailing
slash.

**`django_otp` added to `INSTALLED_APPS`.** `OTPMiddleware` was in the
middleware stack without it. The middleware imports fine and fails only when
it touches the ORM, so the mistake surfaced as a confusing error on the first
request rather than at startup.

**`core/urls.py` crashed on import.** It referenced `views.dashboard_statistics`
and `views.my_classes`, neither of which existed — so `AttributeError` at
import and the whole URLconf failed to load. The template did not start.

**Missing dependencies added.** `pyproject.toml` had no database driver
(`psycopg`), no WSGI server (`gunicorn`), no `djangorestframework`, no
`drf-spectacular`. The documented production deployment could not have run.

**Accessible form field.** The old `Input` component had no `htmlFor`/`id`
pairing (label click did nothing, screen readers announced an unlabelled
field), no `aria-describedby` linking the error, and conveyed errors by colour
alone. All three cost nothing to fix.

**Open redirect closed.** `?next=` is followed only when it starts with a
single `/`. `//evil.com` is protocol-relative and navigates off-site despite
starting with a slash.

**Account enumeration closed.** Password reset shows the same response whether
or not the address exists.

**`revokeObjectURL` after downloads.** Without it, each export pins its full
size in memory for the document's lifetime.

---

## 17. Deferred

Worth having; not built yet.

- **Nonce-based CSP.** The current policy still needs `'unsafe-inline'` for
  scripts because Next.js injects inline bootstrap code. A middleware-issued
  nonce removes it. This is the single biggest remaining frontend security
  improvement.

*(The `entityManager` port that sat here is done — see §20.)*
- **WebSocket client.** The source project has one. Needs Django Channels on
  the backend to be useful, which is a larger decision.
- **`server-api.ts`** for authenticated Server Component fetches. The current
  template is client-fetch-only.
- **Rate limiting beyond DRF throttles.** DRF's are per-view and cache-backed;
  a real deployment wants them at the edge too.

*(The two-user-app question that sat here is resolved — see §19.)*

---

## 18. Domain leakage found and removed

A template's job is to be domain-free. What was actually in there:

| Where | What |
|---|---|
| `apps/core/models.py` | `SystemSettings` with `site_name="School Management System"`, `email_from_name="School Admin"`, `noreply@school.com` |
| `apps/core/permissions.py` | `CanManageIncidents` — "residents can only edit new incidents" |
| `apps/core/urls.py` | `/my-classes/`, `/pending-approvals/` |
| `settingsConfig/api/rest.py` | throttle scopes `content_generation`, `assessment_generation`, `agent_request` |
| `handler/ApiConfig.tsx` | `const BASE_URL = 'https://192.168.0.105:800'` — someone's LAN address |
| `types/index.ts` | `User.referral_code`, `User.referred_by` |
| `Fronted_Web_Template/` | `mpesa_stk_push/stk.php` — a PHP Safaricom integration inside a Next.js template |
| `app/(auth)/` | `Register copy 4/`, and `Reser-Password` (sic) |
| repo root | committed `logs/django.log.2025-11-*`, a `main.py` printing "Hello from django-starter-template!" |

From the source project, additionally caught before it could be carried in:
`BaseModelViewSet` treated `department_id` and `class_group_id` as
special-cased import fields, and `bulk_delete` returned the error message
"…referenced by other records (e.g. active leases)".

Three of these — the school-management defaults, the incident permissions, and
the education throttle scopes — indicate the "template" was extracted from at
least two prior products without a cleaning pass. That is the normal way
templates decay, and it is why this file exists: a pattern is only worth
keeping if someone can state what it is for without naming a product.

**The rule going forward:** anything in `apps/core/` or `lib/` that names a
business entity is a bug. Domain code goes in a domain app.

---

## 19. One user app

**Verdict: merged into `apps.accounts`. `apps.authentication` deleted.**

The template shipped two overlapping user apps and, as shipped, **neither
worked**.

`apps.accounts` was the original: its migration created `User`, `UserRole`,
`UserProfile`, `UserSession`, `LoginAttempt` and `UserRoleHistory`. `User` and
`UserRole` were later lifted out into a new `apps.authentication`, and
`AUTH_USER_MODEL` repointed — but `apps/accounts/models.py` was left
referencing both by bare name, with no definition and no import. The module
raised `NameError` on import, so the app had to be commented out of
`INSTALLED_APPS`. The more complete user app was unreachable, and the
replacement had defects of its own:

- **The primary key could not produce two users.**
  `id = CharField(primary_key=True, max_length=50, db_column="user_id")`,
  documented as "Institutional user ID … e.g. SIG00125" — someone's
  institutional numbering scheme — with **no default**, and `create_user()`
  never set it. The first user got `id=""`; the second violated the unique
  constraint.
- **The project could not be bootstrapped.** `role` was `null=False` with
  `on_delete=PROTECT`. `createsuperuser` cannot supply a role, and no role can
  exist until a user creates one.
- **Soft-deleted users could still sign in.** Declaring a plain
  `BaseUserManager` as `objects` silently overrode
  `SoftDeleteMixin.objects` — and the auth backend looks users up through
  `_default_manager`, so `get_by_natural_key()` found deleted accounts.

All three are fixed: UUID primary key (consistent with `BaseModel`), nullable
`role` with the constraint moved to the application layer where it can return
a useful message, and a `UserManager` built from `SoftDeleteQuerySet` so
deleted users are invisible to authentication while `all_objects` still serves
the admin and restore paths.

### Biometrics removed

The old `accounts` User carried `embedding_vector`, `embedding_hash`,
`face_quality_score`, `face_confidence_score`, `face_enrolled_at`,
`face_enrollment_verified`, `face_last_used` — a facial-recognition enrolment
system, from yet another product (the third distinct domain found in this
"template", after school management and incident tracking).

Removed on two grounds. It is domain leakage; and face embeddings are
special-category personal data under GDPR Article 9, with separate statutory
regimes in several US states. A starter template that ships biometric columns
switched on by default makes every generated project handle biometric data
whether or not it intended to — a compliance obligation acquired by accident.

Usage counts made the call obvious: 1–2 references for the biometric fields
against 15–48 for every field that was kept.

### Two adjacent bugs found while merging

**`apps/core/services/` shadowed `apps/core/services.py`.** Both existed. In
Python the package wins, so the module was unreachable by normal import —
which is why the package's `__init__.py` carried an
`importlib.util.spec_from_file_location` shim loading the shadowed file by
path, wrapped in a bare `except` that set four service classes to `None` on
failure. Deleting the package (which held the biometric code) removed the
collision and the shim together.

**Privilege escalation in `ProfileCompletionService`:**

```python
for key, value in profile_data.items():
    if hasattr(user, key) and value is not None:
        setattr(user, key, value)
```

`profile_data` is request data and `hasattr` is true for every model field, so
a profile update naming `is_superuser`, `is_staff`, `is_approved`, `role_id`
or `password` had it applied. Replaced with an explicit `EDITABLE_FIELDS`
allowlist; ignored keys are logged rather than silently dropped.

### The migration split is load-bearing

Migrations were regenerated as `0001_initial` + `0002_add_otp_device`. **Do
not squash them.** `django_otp`'s `TOTPDevice` has its own FK to
`AUTH_USER_MODEL`, so declaring `User.otp_device` in the initial migration
makes `accounts.0001` and `otp_totp.0001` mutually dependent — Django rejects
the entire graph with `CircularDependencyError` and nothing migrates at all.
Creating the `User` table first and adding the field in a follow-up is the
documented escape. The original authors had this right; it was worth
re-deriving to understand why.

Verified end to end against a real database: migrate, `createsuperuser`,
`create_user` with password hashing, role checks, soft delete hiding the user
from `get_by_natural_key()`, restore, and `select_related("role", "otp_device")`.

Full detail: `django_starter_template/docs/AUTH_APP_CONSOLIDATION.md`.


---

## 20. The entity layer

**Verdict: rebuilt. 21,892 lines → ~3,100 (14%, tests included), same capability.**

The source project's `components/entityManager/` generated CRUD screens from a
declarative config. The instinct is right: hand-writing a filtered, sorted,
paginated table plus a form plus a detail view for twenty resources produces
twenty subtly different implementations and twenty places to fix the same
pagination bug.

The execution had six problems, all measured rather than asserted.

### Four thousand lines were never imported

Across 194 consuming files the entire public surface was `EntityManager` (90
imports), `createHttpClient` (28), and some types. Meanwhile:

| Module | Lines | Consumer imports |
|---|---|---|
| `EntityConfigBuilder` | 477 | 0 |
| `ActionBuilder` | 426 | 0 |
| `FieldBuilder` | 294 | 0 |
| `EntityStateProvider` | 378 | 0 |
| `useEntityCache` | 315 | 0 |
| `EntityImporter` | 663 | 0 |
| `BulkActions` | 216 | 0 |
| `ColumnBuilder`, `InlineEdit`, `useTouchGestures`, `useResponsiveView` | — | 0 |

The fluent builder API is the clearest case: written, documented, never
called. Every call site passes a plain object literal. Builders exist because
"config objects are hard to type" — but the fix for that is to type the config
object, which costs nothing at runtime.

### The entry point disabled type checking, so the library guessed

```ts
// Accept either canonical config or legacy/compact shapes during migration
config: EntityManagerConfig<T> | Record<string, unknown>;
```

`Record<string, unknown>` at the main boundary means all 90 call sites were
unchecked. Hence a ~100-line runtime normalizer:

```ts
const list = entity.list ?? entity.columns ?? entity.listConfig ?? entity.listColumns;
const view = entity.view ?? entity.viewFields ?? entity.viewConfig;
```

**Four accepted spellings of one key.** This is §1's failure with the arrow
reversed: there, six response shapes forced the *client* to guess; here, no
committed config shape forced the *library* to guess what the consumer meant.

The cost is not the normalizer. It is that `listColumn` — singular, a typo —
renders an empty table silently, at runtime, in production.

The rewrite types keys as `keyof T`. That typo is now a compile error. Two
genuine bugs surfaced the moment the example page was typechecked against it.

### Three parallel type systems, one shadowing a directory

`primitives/types/config.ts` (`singular`, `searchEnabled`),
`primitives/types.ts` — **a file beside the `primitives/types/` directory**,
the same package-shadows-module collision found in `apps/core/services` (§19)
— and `composition/config/types.ts`, the one actually used, spelling the same
concepts `label` and `searchable`. A consumer reading the file that looks
canonical would write a config the orchestrator rejects.

### Most of the configurable surface was never configured

| | Defined | Used |
|---|---|---|
| View modes | 8 | 3 (`table` 8×, `gallery` 2×, `card` 1×) |
| Form layouts | 5 | 3 |
| Field types | 33 | ~18 |

`components/list/index.tsx` is 2,296 lines, carrying five view modes nobody
asked for. The rewrite ships twelve column formats and thirteen field types
plus a `custom` escape hatch — which is what makes a short built-in list
sufficient, and which 20 call sites already used.

### The form reimplemented its own dependencies

1,507 lines of hand-rolled form state plus 246 of hand-rolled validation,
while `react-hook-form` and `zod` were already in `package.json`. The file's
own header documents three bugs it had to fix: missing `autoComplete`, clicks
bubbling into an accidental submit, and a `useMemo` keyed on the whole values
object so every field re-rendered when any field changed. The first and third
cannot occur with react-hook-form — it registers native inputs and is
uncontrolled by default.

### The orchestrator forced every call site to describe every view

A create-only screen still had to pass `list: { columns: [] }`,
`view: { fields: [] }` and `actions: { actions: [] }`. The rewrite exports
three standalone components; a page declares only what it renders, and view
routing stays in the router, where Next.js already handles URLs, the back
button and code splitting better than a `useState<'list'|'create'>` can.

### What was kept

Everything that was real operational knowledge: automatic `FormData`
conversion when a payload contains a `File` (with `Content-Type` left unset so
the browser supplies the boundary), Django filter-lookup syntax, the mobile
card fallback for tables, per-field re-render isolation, and `custom`
renderers.

### What was added

- **List state lives in the URL.** Page, search and ordering are query
  parameters, so a filtered view is linkable and survives the back button. The
  original held them in `useState`, so opening a row and going back dropped
  the user on page 1 of an unsorted list.
- **Accessibility that a table needs and rarely gets:** `aria-sort` on
  sortable headers, a genuinely indeterminate select-all checkbox, `aria-busy`
  skeletons sized to the page so data arrival causes no layout shift, and
  `<dl>` markup for detail views.
- **Selection tracked by id, not row object** — a row from page 1 is a stale
  snapshot by page 3, and identity comparison across refetches drops
  selections silently.
- **Cached `Intl` formatters.** Constructing `Intl.NumberFormat` dominates its
  cost; one per cell means 160 constructions per render of a 20×8 table.

### Second pass: auditing the rewrite against its own claims

Re-reading the first pass found three documented features that had not been
built. Worth recording, because the failure mode generalises — a rewrite that
states its intentions clearly reads like a rewrite that implemented them.

- **`FormData` conversion was documented, not implemented.** Mutations took
  `TInput | FormData`, so callers had to build multipart by hand. Now
  `lib/api/form-data.ts`, with the silent-corruption cases pinned by tests:
  `false` and `0` surviving (a truthiness guard drops them, so unchecking a
  box appears to do nothing), explicit `null` → `''` meaning *clear* while
  `undefined` is omitted meaning *leave alone*, `Date` → ISO 8601 rather than
  a locale string, arrays repeating the key for `QueryDict.getlist()`.
- **`type: 'file'` was broken end to end.** It fell through to the generic
  input branch, where `register()` yields a `FileList` rather than a `File`
  and nothing unwrapped it. `FileField` now unwraps via `Controller`, shows
  the existing value when editing (so saving does not silently clear an
  avatar), and can clear a selection — which an uncontrolled file input
  cannot.
- **Filters were declared and never wired.** `EntityListState.filters`
  existed with nothing writing to it. Now a typed `FilterConfig` with Django
  lookups (`price__gte`), URL-backed like the rest of the list state. No
  `date-range` type: a range is two filters, which composes without a special
  case and lets each end carry its own label.

Also fixed while verifying: **the template could not build without network
access.** `next/font/google` downloads font files at build time, so
`docker build` with no egress, CI behind a proxy, and any offline build all
failed — with a webpack error that does not mention the network. Replaced
with a system font stack, which also removes the bundle cost and the
font-swap layout shift; `app/layout.tsx` documents `next/font/local` for
projects that want a real typeface.

Verified: `tsc --noEmit` clean, `next build` clean with zero warnings, 39
tests passing. Tests cover the pure logic (`form-data`, `format`,
`filterParamName`) and the list's accessibility contract — `aria-sort`, a
keyboard-reachable sort button, the indeterminate select-all checkbox — all
of which look correct visually while being broken for assistive technology.
The worked example (`app/(app)/products/page.tsx`) exercises typed columns,
formatters, badges, filters, export, row and bulk actions, a zod schema and
the detail view, so the layer cannot silently rot.

### Third pass: the decisive evidence was in the same repository

The first two passes argued from usage counts inside `entityManager`. Looking
instead at what the source project's developers did when they had a choice
produced a better argument than any line count.

Alongside the 21,892-line framework, `components/modules/_shared/` exists —
**1,340 lines, thirteen files** — and it has *more* adoption:

| | Lines | Files importing it |
|---|---|---|
| `entityManager` | 21,892 | 179 |
| `_shared` | 1,340 | 237 |

`_shared` leads in four of the five modules that use either. Whole feature
areas are built on it alone: the invoicing module declares
`FinanceManagerColumn[]` from `_shared/types.ts` and never imports
`entityManager`.

And `_shared` is not a framework. It is thirteen composable presentational
components — `EntityShell`, `EntityHeader`, `EntityTabs`, `InfoGrid`,
`StatCard`, `ActionMenu`, `EmptyState`, `SlidingPanel` — each doing one visual
job, with no config normalizer, no builders and no orchestrator.

**Adoption is a revealed preference, and it is much harder to argue with than
a line count.** Given a config-driven monolith that generated whole screens
and a handful of small components that generated nothing, the team reached for
the small components more often — while the monolith's builder layer went to
zero call sites.

The instinct behind `entityManager` was right; the form was wrong.
Config-driven generation earns its place exactly where the shape genuinely
repeats — a paginated table, a validated form — and becomes a liability
everywhere else, because every screen that does not fit has to be argued past
the framework rather than simply composed. That is the case for exporting
`<EntityList>`, `<EntityForm>` and `<EntityView>` independently rather than an
`<EntityManager>` that owns the screen, and the evidence for it was sitting in
the same repository the whole time.

Two gaps `_shared` exposed, both closed: an **overflow action menu** (real
modules declare 2–4 row actions each, 86 across the app; `_shared/types.ts`
carries an `inMenu` flag for the same reason) with the keyboard contract
hand-rolled menus miss — arrow-key cycling, Escape returning focus to the
trigger, outside-click on `mousedown` so the dismissing click does not also
activate what is beneath — and **grouped detail fields** via
`ColumnConfig.section`, since every finance module had a `view/tabs.tsx`
splitting a long record into groups.

Deliberately not adopted: `SlidingPanel` (a drawer is a routing decision, and
Next.js parallel routes do it better), `StatusTimeline` (domain-shaped), and
`EntityShell`/`EntityHeader`/`EntityBreadcrumb` — page chrome belongs to the
app's layout, and pulling it into an entity library is precisely how a CRUD
helper becomes a framework that owns your page.

### Closing the audit

A systematic sweep of `entityManager/index.ts` — the original's complete
public surface — against the replacement confirms nothing is unreachable.
Every component maps (`EntityList`, `EntityForm`, `EntityView`,
`EntityActions` → `ActionMenu`, `EntityExporter` → `exportFormats`/
`onExport`); every primitive hook (`useFilters`, `usePagination`,
`useSelection`, `useSort`) is folded into `useEntityList`, URL-backed;
validation is zod and formatting is `lib/entity/format.ts`. The three things
genuinely gone — the builder layer, the state/API providers, and
`InlineEdit`/`EntityImporter`/`useTouchGestures`/`useResponsiveView` — had
**zero call sites each** in the project that shipped them.

The remaining differences are deliberate: composition instead of
orchestration; headings instead of view tabs; and export allowlists enforced
on the **server** rather than declared on the client. That last one matters —
the source project declared exportable fields client-side, which is a
suggestion; `BaseModelViewSet.export_fields` is a control (§8).

Final: **~3,100 lines against 21,892 — 14%**, including a test suite the
original's equivalent modules did not have. 47 tests, clean typecheck, clean
build with zero warnings.

Full analysis: `Fronted_Web_Template/next_template/lib/entity/ANALYSIS.md`.
