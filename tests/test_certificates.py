from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from django.contrib.admin import AdminSite
from django.contrib.auth.models import User
from django.core.files import File
from django.test import RequestFactory, TestCase, TransactionTestCase

import pytest
from cryptography.x509 import Certificate as CryptographyCertificate
from privates.test import temp_private_root

from simple_certmanager.admin import CertificateAdmin
from simple_certmanager.constants import CertificateTypes
from simple_certmanager.forms import CertificateAdminForm
from simple_certmanager.models import Certificate
from simple_certmanager.test.certificate_generation import key_to_pem

TEST_FILES = Path(__file__).parent / "data"


@pytest.fixture
def cert_with_keypair(db, temp_private_root, leaf_keypair):
    key, cert_pem = leaf_keypair
    key_pem = key_to_pem(key)
    return Certificate.objects.create(
        label="Test certificate",
        type=CertificateTypes.key_pair,
        public_certificate=File(BytesIO(cert_pem), name="cert.pem"),
        private_key=File(BytesIO(key_pem), name="key.pem"),
    )


@temp_private_root()
class CertificateTests(TestCase):
    def test_calculated_properties(self):
        with (
            open(TEST_FILES / "test.certificate", "rb") as client_certificate_f,
            open(TEST_FILES / "test.key", "rb") as key_f,
        ):
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.key_pair,
                public_certificate=File(client_certificate_f, name="test.certificate"),
                private_key=File(key_f, name="test.key"),
            )

        self.assertEqual(
            certificate.expiry_date,
            datetime(2023, 2, 21, 14, 26, 51, tzinfo=timezone.utc),
        )
        self.assertEqual(
            "C: NL, ST: Some-State, O: Internet Widgits Pty Ltd", certificate.issuer
        )
        self.assertEqual(
            "C: NL, ST: Some-State, O: Internet Widgits Pty Ltd", certificate.subject
        )
        self.assertRegex(certificate.serial_number, r"[0-9A-F]{2}(?::[0-9A-F]{2}){15}")

    def test_creating_empty_admin_detail(self):
        form = CertificateAdminForm()
        self.assertInHTML("Serial number:", form.as_p())

    def test_creating_valid_key_pair(self):
        with (
            open(TEST_FILES / "test.certificate", "rb") as client_certificate_f,
            open(TEST_FILES / "test.key", "rb") as key_f,
        ):
            form = CertificateAdminForm(
                data={
                    "label": "Test valid pair",
                    "type": CertificateTypes.key_pair,
                },
                files={
                    "public_certificate": File(client_certificate_f),
                    "private_key": File(key_f),
                },
                instance=None,
            )
        self.assertTrue(form.is_valid())

    def test_admin_detail_contains_serial_number(self):
        with open(TEST_FILES / "test.certificate", "rb") as client_certificate_f:
            form = CertificateAdminForm(
                {
                    "label": "Test valid certificate",
                    "type": CertificateTypes.cert_only,
                },
                {"public_certificate": File(client_certificate_f)},
            )

        self.assertInHTML("Serial number:", form.as_p())

    def test_admin_validation_invalid_certificate(self):
        with open(TEST_FILES / "invalid.certificate", "rb") as client_certificate_f:
            form = CertificateAdminForm(
                {
                    "label": "Test invalid certificate",
                    "type": CertificateTypes.cert_only,
                },
                {"public_certificate": File(client_certificate_f)},
            )

        self.assertFalse(form.is_valid())

    def test_admin_validation_valid_certificate(self):
        with open(TEST_FILES / "test.certificate", "rb") as client_certificate_f:
            form = CertificateAdminForm(
                {
                    "label": "Test valid certificate",
                    "type": CertificateTypes.cert_only,
                },
                {"public_certificate": File(client_certificate_f)},
            )

        self.assertTrue(form.is_valid())

    def test_invalid_key_pair(self):
        with (
            open(TEST_FILES / "test.certificate", "rb") as client_certificate_f,
            open(TEST_FILES / "test2.key", "rb") as key_f,
        ):
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.key_pair,
                public_certificate=File(client_certificate_f, name="test.certificate"),
                private_key=File(key_f, name="test2.key"),
            )

        self.assertFalse(certificate.is_valid_key_pair())

    def test_valid_key_pair(self):
        with (
            open(TEST_FILES / "test.certificate", "rb") as client_certificate_f,
            open(TEST_FILES / "test.key", "rb") as key_f,
        ):
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.key_pair,
                public_certificate=File(client_certificate_f, name="test.certificate"),
                private_key=File(key_f, name="test.key"),
            )

        self.assertTrue(certificate.is_valid_key_pair())

    def test_valid_key_pair_missing_key(self):
        with open(TEST_FILES / "test.certificate", "rb") as client_certificate_f:
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.key_pair,
                public_certificate=File(client_certificate_f, name="test.certificate"),
            )

        self.assertIsNone(certificate.is_valid_key_pair())

    def test_admin_changelist_doesnt_crash_on_missing_files(self):
        # Github #39
        with (
            open(TEST_FILES / "test.certificate", "rb") as client_certificate_f,
            open(TEST_FILES / "test.key", "rb") as key_f,
        ):
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

    def test_invalid_private_key(self):
        """Assert that invalid private keys cannot be uploaded

        The test file contains a valid public cert, which is invalid when used
        as a private key."""

        with open(TEST_FILES / "test.certificate", "rb") as cert:
            form = CertificateAdminForm(
                {
                    "label": "Test invalid private key",
                    "type": CertificateTypes.key_pair,
                },
                {
                    "public_certificate": File(cert),
                    "private_key": File(cert),
                },
            )

        self.assertEqual(len(form.errors), 1)
        self.assertIsNotNone(form.errors["private_key"])


@temp_private_root()
class TestCertificateFilesDeletion(TransactionTestCase):
    def test_certificate_deletion_deletes_files(self):
        with open(TEST_FILES / "test.certificate", "rb") as certificate_f:
            certificate = Certificate.objects.create(
                label="Test client certificate",
                type=CertificateTypes.cert_only,
                public_certificate=File(certificate_f, name="test.certificate"),
            )

        file_path = certificate.public_certificate.path
        storage = certificate.public_certificate.storage

        certificate.delete()

        self.assertFalse(storage.exists(file_path))


def test_load_certificate_ok(cert_with_keypair: Certificate):
    result = cert_with_keypair.certificate

    assert isinstance(result, CryptographyCertificate)


def test_load_certificate_no_certificate():
    instance = Certificate(public_certificate="", type=CertificateTypes.cert_only)

    with pytest.raises(ValueError):
        instance.certificate


@pytest.mark.django_db
def test_load_certificate_invalid_certificate():
    instance = Certificate.objects.create(
        label="Test certificate",
        type=CertificateTypes.cert_only,
        public_certificate=File(BytesIO(b"bwoken"), name="cert.pem"),
    )

    with pytest.raises(ValueError):
        instance.certificate
