from django.core.management.base import BaseCommand
from django.db import connection


class Command(BaseCommand):
    help = 'Fix django_otp migration dependency issue'

    def handle(self, *args, **options):
        with connection.cursor() as cursor:
            # Create the TOTPDevice table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS "django_otp_totpdevice" (
                    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
                    "name" varchar(64) NOT NULL,
                    "confirmed" bool NOT NULL,
                    "throttling_failure_timestamp" datetime NULL,
                    "throttling_failure_count" integer unsigned NOT NULL CHECK ("throttling_failure_count" >= 0),
                    "created_at" datetime NULL,
                    "last_used_at" datetime NULL,
                    "key" varchar(80) NOT NULL,
                    "step" smallint unsigned NOT NULL CHECK ("step" >= 0),
                    "t0" bigint NOT NULL,
                    "digits" smallint unsigned NOT NULL CHECK ("digits" >= 0),
                    "tolerance" smallint unsigned NOT NULL CHECK ("tolerance" >= 0),
                    "drift" smallint NOT NULL,
                    "last_t" bigint NOT NULL,
                    "user_id" char(32) NOT NULL REFERENCES "accounts_user" ("id") DEFERRABLE INITIALLY DEFERRED
                )
            ''')

            # Create the index
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS "django_otp_totpdevice_user_id_e57a87c0"
                ON "django_otp_totpdevice" ("user_id")
            ''')

            # Mark django_otp.0001_initial as applied in django_migrations table
            cursor.execute('''
                INSERT OR IGNORE INTO django_migrations (app, name, applied)
                VALUES ('django_otp', '0001_initial', datetime('now'))
            ''')

        self.stdout.write(
            self.style.SUCCESS('Successfully created TOTPDevice table and marked django_otp migration as applied')
        )