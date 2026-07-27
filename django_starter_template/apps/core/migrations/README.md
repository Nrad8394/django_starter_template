# apps.core migrations

Empty on purpose.

`apps/core/models.py` contains only abstract base classes — `BaseModel`,
`SoftDeleteMixin`, `SingletonModel` and friends. Abstract models create no
tables, so `core` has nothing to migrate.

The previous `0001_initial.py` created a concrete `SystemSettings` table whose
defaults were `site_name="School Management System"` and
`email_from_address="noreply@school.com"` — a different product's
configuration, inherited by every project generated from this template. Both
the model and its migration are gone.

If you want a settings table, subclass `SingletonModel` **in your own app**,
where the field names and defaults describe your product:

```python
# apps/branding/models.py
from apps.core.models import SingletonModel

class BrandingSettings(SingletonModel):
    CACHE_KEY = "branding_settings"
    support_email = models.EmailField(default="")
    site_name = models.CharField(max_length=255, default="")
```

Then `python manage.py makemigrations branding`.
