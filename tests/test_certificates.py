from datetime import datetime
from pathlib import Path

from django.contrib.admin import AdminSite
from django.contrib.auth.models import User
from django.core.files import File
from django.test import RequestFactory, TestCase, TransactionTestCase

from privates.test import temp_private_root

from simple_certmanager.admin import CertificateAdmin
from simple_certmanager.constants import CertificateTypes
from simple_certmanager.forms import CertificateAdminForm
from simple_certmanager.models import Certificate

TEST_FILES = Path(__file__).parent / "data"


@temp_private_root()
class CertificateTests(TestCase):
    def test_calculated_properties(self):
        with open(TEST_FILES / "test.certificate", "r") as client_certificate_f, open(
            TEST_FILES / "test.key", "r"
        ) as key_f:
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.key_pair,
                public_certificate=File(client_certificate_f, name="test.certificate"),
                private_key=File(key_f, name="test.key"),
            )

        self.assertEqual(datetime(2023, 2, 21, 14, 26, 51), certificate.expiry_date)
        self.assertEqual(
            "C: NL, ST: Some-State, O: Internet Widgits Pty Ltd", certificate.issuer
        )
        self.assertEqual(
            "C: NL, ST: Some-State, O: Internet Widgits Pty Ltd", certificate.subject
        )

    def test_admin_validation_invalid_certificate(self):
        with open(TEST_FILES / "invalid.certificate", "r") as client_certificate_f:
            form = CertificateAdminForm(
                {
                    "label": "Test invalid certificate",
                    "type": CertificateTypes.cert_only,
                },
                {"public_certificate": File(client_certificate_f)},
            )

        self.assertFalse(form.is_valid())

    def test_admin_validation_valid_certificate(self):
        with open(TEST_FILES / "test.certificate", "r") as client_certificate_f:
            form = CertificateAdminForm(
                {
                    "label": "Test invalid certificate",
                    "type": CertificateTypes.cert_only,
                },
                {"public_certificate": File(client_certificate_f)},
            )

        self.assertTrue(form.is_valid())

    def test_invalid_key_pair(self):
        with open(TEST_FILES / "test.certificate", "r") as client_certificate_f, open(
            TEST_FILES / "test2.key", "r"
        ) as key_f:
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.key_pair,
                public_certificate=File(client_certificate_f, name="test.certificate"),
                private_key=File(key_f, name="test2.key"),
            )

        self.assertFalse(certificate.is_valid_key_pair())

    def test_valid_key_pair(self):
        with open(TEST_FILES / "test.certificate", "r") as client_certificate_f, open(
            TEST_FILES / "test.key", "r"
        ) as key_f:
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.key_pair,
                public_certificate=File(client_certificate_f, name="test.certificate"),
                private_key=File(key_f, name="test.key"),
            )

        self.assertTrue(certificate.is_valid_key_pair())

    def test_valid_key_pair_missing_key(self):
        with open(TEST_FILES / "test.certificate", "r") as client_certificate_f:
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.key_pair,
                public_certificate=File(client_certificate_f, name="test.certificate"),
            )

        self.assertIsNone(certificate.is_valid_key_pair())

    def test_admin_changelist_doesnt_crash_on_missing_files(self):
        # Github #39
        with open(TEST_FILES / "test.certificate", "r") as client_certificate_f, open(
            TEST_FILES / "test.key", "r"
        ) as key_f:
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.key_pair,
                public_certificate=File(client_certificate_f, name="test.certificate"),
                private_key=File(key_f, name="test.key"),
            )

        # delete the physical files from media storage
        Path(certificate.public_certificate.path).unlink()
        Path(certificate.private_key.path).unlink()

        certificate_admin = CertificateAdmin(model=Certificate, admin_site=AdminSite())

        # fake a superuser admin request to changelist
        request = RequestFactory().get("/dummy")
        request.user = User.objects.create_user(is_superuser=True, username="admin")
        response = certificate_admin.changelist_view(request)

        # calling .render() to force actual rendering and trigger issue
        response.render()

        self.assertEqual(response.status_code, 200)


@temp_private_root()
class TestCertificateFilesDeletion(TransactionTestCase):
    def test_certificate_deletion_deletes_files(self):
        with open(TEST_FILES / "test.certificate", "r") as certificate_f:
            certificate = Certificate.objects.create(
                label="Test client certificate",
                type=CertificateTypes.cert_only,
                public_certificate=File(certificate_f, name="test.certificate"),
            )

        file_path = certificate.public_certificate.path
        storage = certificate.public_certificate.storage

        certificate.delete()

        self.assertFalse(storage.exists(file_path))