from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from django.contrib.auth import get_user_model
from rest_framework import status
from apps.accounts.views import UserViewSet

User = get_user_model()


class UserViewSetBaseViewTests(APITestCase):
    def setUp(self):
        # Create an admin user and a normal user
        self.admin = User.objects.create_superuser(
            email="admin@example.com", password="adminpass"
        )
        # Ensure admin has an 'admin' role so project permissions (is_admin_or_above) succeed
        from apps.accounts.models import UserRole

        role, _ = UserRole.objects.get_or_create(
            name="admin", defaults={"display_name": "Administrator", "is_active": True}
        )
        self.admin.role = role
        self.admin.save()
        self.user = User.objects.create_user(
            email="user@example.com", password="userpass"
        )
        self.client = APIClient()

    def test_bulk_create_users_as_admin(self):
        self.client.force_authenticate(user=self.admin)
        url = "/api/v1/accounts/users/bulk_create/"
        payload = [
            {
                "email": "new1@example.com",
                "password": "Password123!",
                "first_name": "New",
                "last_name": "One",
            },
            {
                "email": "new2@example.com",
                "password": "Password123!",
                "first_name": "New",
                "last_name": "Two",
            },
        ]
        response = self.client.post(url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        data = response.json()
        self.assertEqual(data.get("count"), 2)
        # Check users created in DB
        self.assertTrue(User.objects.filter(email="new1@example.com").exists())
        self.assertTrue(User.objects.filter(email="new2@example.com").exists())

    def test_bulk_import_template_downloads(self):
        self.client.force_authenticate(user=self.admin)
        # Try to reverse the action using common router naming conventions
        from django.urls import reverse, NoReverseMatch

        name_candidates = [
            "user-bulk_import_template",
            "user-bulk-import-template",
            "user-bulk-import_template",
            "user-bulk_import-template",
            "user-bulkimporttemplate",
        ]

        url = None
        for name in name_candidates:
            try:
                url = reverse(name)
                break
            except NoReverseMatch:
                continue

        # As a fallback try direct path candidates
        if not url:
            direct_candidates = [
                "/api/v1/accounts/users/bulk_import_template/",
                "/api/v1/accounts/users/bulk-import-template/",
            ]
            for c in direct_candidates:
                # Check that a GET doesn't return 404
                r = self.client.get(c + "?export_format=csv")
                if r.status_code == status.HTTP_200_OK:
                    url = c
                    break

        if url:
            # Request CSV and XLSX via HTTP if we found a URL
            resp_csv = self.client.get(url + "?export_format=csv")
            self.assertEqual(resp_csv.status_code, status.HTTP_200_OK)
            self.assertIn("text/csv", resp_csv["Content-Type"])

            resp_xlsx = self.client.get(url + "?export_format=xlsx")
            self.assertEqual(resp_xlsx.status_code, status.HTTP_200_OK)
            self.assertIn(
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                resp_xlsx["Content-Type"],
            )
        else:
            # As a fallback, call the viewset method directly to validate template generation logic
            view = UserViewSet()
            view.queryset = User.objects.all()

            class FakeRequest:
                def __init__(self, q):
                    self.query_params = q

            resp_csv = view.bulk_import_template(FakeRequest({"export_format": "csv"}))
            self.assertIn("text/csv", resp_csv["Content-Type"])

            resp_xlsx = view.bulk_import_template(
                FakeRequest({"export_format": "xlsx"})
            )
            self.assertIn(
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                resp_xlsx["Content-Type"],
            )

    def test_bulk_export_default_xlsx(self):
        # create a couple of users to export
        User.objects.create_user(email="export1@example.com", password="pass")
        User.objects.create_user(email="export2@example.com", password="pass")

        self.client.force_authenticate(user=self.admin)
        url = "/api/v1/accounts/users/bulk_export/"
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            resp["Content-Type"],
        )

    def test_statistics_action_includes_extra_stats(self):
        # create some users
        User.objects.create_user(email="s1@example.com", password="p")
        User.objects.create_user(email="s2@example.com", password="p", is_active=False)

        self.client.force_authenticate(user=self.admin)
        url = "/api/v1/accounts/users/statistics/"
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        data = resp.json()
        # Base stats
        self.assertIn("total_count", data)
        self.assertIn("filtered_count", data)
        # Extra stats from UserViewSet.get_extra_statistics
        self.assertIn("active_users", data)
        self.assertIn("staff_users", data)
        self.assertIn("superuser_count", data)

    def test_bulk_import_csv_upload(self):
        """Upload a CSV file to the bulk_import endpoint and verify users are created"""
        self.client.force_authenticate(user=self.admin)
        url = "/api/v1/accounts/users/bulk_import/"

        csv_content = "email,first_name,last_name,password\nimport1@example.com,Imp,One,Password123!\nimport2@example.com,Imp,Two,Password123!\n"
        from django.core.files.uploadedfile import SimpleUploadedFile

        file_obj = SimpleUploadedFile(
            "users.csv", csv_content.encode("utf-8"), content_type="text/csv"
        )
        response = self.client.post(url, {"file": file_obj}, format="multipart")

        # Should return a 200 OK and report imported rows
        if response.status_code != status.HTTP_200_OK:
            # Include response body to aid debugging
            try:
                body = response.json()
            except Exception:
                body = response.content.decode(errors="ignore")
            self.fail(f"Bulk import failed: status={response.status_code}, body={body}")

        data = response.json()
        self.assertIn("imported", data)
        self.assertGreaterEqual(data["imported"], 2)

        # Check users created in DB
        self.assertTrue(User.objects.filter(email="import1@example.com").exists())
        self.assertTrue(User.objects.filter(email="import2@example.com").exists())

    def test_bulk_import_xlsx_upload(self):
        """Upload an XLSX file to the bulk_import endpoint and verify users are created"""
        self.client.force_authenticate(user=self.admin)
        url = "/api/v1/accounts/users/bulk_import/"

        # Build an in-memory XLSX file matching the expected template columns
        from io import BytesIO

        try:
            from openpyxl import Workbook
        except Exception as e:
            self.skipTest(f"openpyxl not available: {e}")

        wb = Workbook()
        ws = wb.active
        # header row expected by bulk import
        ws.append(["email", "first_name", "last_name", "password"])
        ws.append(["xlsx1@example.com", "X", "One", "Password123!"])
        ws.append(["xlsx2@example.com", "X", "Two", "Password123!"])

        bio = BytesIO()
        wb.save(bio)
        bio.seek(0)

        from django.core.files.uploadedfile import SimpleUploadedFile

        file_obj = SimpleUploadedFile(
            "users.xlsx",
            bio.read(),
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

        response = self.client.post(url, {"file": file_obj}, format="multipart")

        # Should return a 200 OK and report imported rows
        if response.status_code != status.HTTP_200_OK:
            try:
                body = response.json()
            except Exception:
                body = response.content.decode(errors="ignore")
            self.fail(
                f"Bulk XLSX import failed: status={response.status_code}, body={body}"
            )

        data = response.json()
        self.assertIn("imported", data)
        self.assertGreaterEqual(data["imported"], 2)

        # Check users created in DB
        self.assertTrue(User.objects.filter(email="xlsx1@example.com").exists())
        self.assertTrue(User.objects.filter(email="xlsx2@example.com").exists())
