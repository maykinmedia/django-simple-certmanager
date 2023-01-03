from pathlib import Path
from unittest import expectedFailure

from django.contrib.admin import AdminSite
from django.contrib.auth.models import User
from django.core.files import File
from django.test import Client, TestCase
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from privates.test import temp_private_root
from pyquery import PyQuery as pq

from simple_certmanager.admin import CertificateAdmin
from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate

TEST_FILES = Path(__file__).parent / "data"


@temp_private_root()
class AdminTests(TestCase):
    def test_list_view(self):
        """Assert that certificates are correctly displayed in the list view"""

        with open(TEST_FILES / "test.certificate", "r") as client_certificate_f:
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.key_pair,
                public_certificate=File(client_certificate_f, name="test.certificate"),
            )

        CertificateAdmin(model=Certificate, admin_site=AdminSite())

        User.objects.create_superuser(username="admin", password="secret")
        client = Client()
        client.login(username="admin", password="secret")

        # check response
        url = reverse("admin:simple_certmanager_certificate_changelist")

        response = client.get(url)

        self.assertEqual(response.status_code, 200)

        # check that certificate is correctly displayed
        html = response.content.decode("utf-8")
        doc = pq(html)
        fields = doc(".field-get_label")
        anchor = fields[0].getchildren()[0]

        self.assertEqual(anchor.tag, "a")
        self.assertEqual(anchor.text, certificate.label)

    def test_detail_view(self):
        """Assert that public certificates and private keys are correctly displayed in
        the Admin's change_view, but no download link is present for the private key

        The functionality for the private key is implemented and tested in django-
        privates, but we need to make sure that `private_media_no_download_fields` has
        actually been set in this library."""

        with open(TEST_FILES / "test.certificate", "r") as client_certificate_f, open(
            TEST_FILES / "test.key", "r"
        ) as key_f:
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.key_pair,
                public_certificate=File(client_certificate_f, name="test.certificate"),
                private_key=File(key_f, name="test.key"),
            )

        CertificateAdmin(model=Certificate, admin_site=AdminSite())

        User.objects.create_superuser(username="admin", password="secret")
        client = Client()
        client.login(username="admin", password="secret")

        # check response
        url = reverse(
            "admin:simple_certmanager_certificate_change", args=(certificate.pk,)
        )

        response = client.get(url)

        self.assertEqual(response.status_code, 200)

        # parse content
        html = response.content.decode("utf-8")
        doc = pq(html)
        uploads = doc(".file-upload")

        # check that public certificate is correctly displayed with link
        anchor = uploads.children()[0]

        self.assertEqual(anchor.tag, "a")
        self.assertEqual(anchor.text, certificate.public_certificate.name)

        # check that private key is correctly displayed without link
        pk = uploads[1]

        display_value = pk.text.strip()

        self.assertEqual(pk.tag, "p")
        self.assertEqual(
            display_value, _("Currently: %s") % certificate.private_key.name
        )

    def test_list_view_invalid_public_cert(self):
        """Assert that `changelist_view` works if DB contains a corrupted public cert"""

        with open(TEST_FILES / "invalid.certificate", "r") as client_certificate_f:
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.cert_only,
                public_certificate=File(
                    client_certificate_f, name="invalid.certificate"
                ),
            )

        CertificateAdmin(model=Certificate, admin_site=AdminSite())

        User.objects.create_superuser(username="admin", password="secret")
        client = Client()
        client.login(username="admin", password="secret")

        # check response
        url = reverse("admin:simple_certmanager_certificate_changelist")

        # check that response is OK and invalid certificate is logged
        with self.assertLogs("simple_certmanager.utils", level="WARNING") as logs:
            response = client.get(url)

            self.assertEqual(response.status_code, 200)

            expected_log_msg = _("invalid certificate: %s") % certificate.label
            self.assertEqual(
                logs.output[0], "WARNING:simple_certmanager.utils:%s" % expected_log_msg
            )

    def test_list_view_invalid_private_key(self):
        """Assert that `changelist_view` works if DB contains a corrupted private key"""

        with open(TEST_FILES / "test.certificate", "r") as client_certificate_f, open(
            TEST_FILES / "invalid.certificate", "r"
        ) as key_f:
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.key_pair,
                public_certificate=File(
                    client_certificate_f, name="invalid.certificate"
                ),
                private_key=File(key_f, name="test.key"),
            )

        CertificateAdmin(model=Certificate, admin_site=AdminSite())

        User.objects.create_superuser(username="admin", password="secret")
        client = Client()
        client.login(username="admin", password="secret")

        # check response
        url = reverse("admin:simple_certmanager_certificate_changelist")

        # check that response is OK and invalid certificate is logged
        with self.assertLogs("simple_certmanager.utils", level="WARNING") as logs:
            response = client.get(url)

            self.assertEqual(response.status_code, 200)

            expected_log_msg = _("invalid certificate: %s") % certificate.label
            self.assertEqual(
                logs.output[0], "WARNING:simple_certmanager.utils:%s" % expected_log_msg
            )

    @expectedFailure
    def test_detail_view_invalid_public_cert(self):
        """Assert that `change_view` works if DB contains a corrupted public cert

        The test currently fails because the workaround for corrupted data only
        patches the admin and doesn't touch the models. This is not an immediate
        concern, but the test is kept in place for the purpose of documentation."""

        with open(TEST_FILES / "invalid.certificate", "r") as client_certificate_f:
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.cert_only,
                public_certificate=File(
                    client_certificate_f, name="invalid.certificate"
                ),
            )

        CertificateAdmin(model=Certificate, admin_site=AdminSite())

        User.objects.create_superuser(username="admin", password="secret")
        client = Client()
        client.login(username="admin", password="secret")

        # check response
        url = reverse(
            "admin:simple_certmanager_certificate_change", args=(certificate.pk,)
        )

        # check that response is OK and invalid certificate is logged
        with self.assertLogs("simple_certmanager.utils", level="WARNING") as logs:
            response = client.get(url)

            self.assertEqual(response.status_code, 200)

            expected_log_msg = _("invalid certificate: %s") % certificate.label
            self.assertEqual(
                logs.output[0], "WARNING:simple_certmanager.utils:%s" % expected_log_msg
            )

    def test_detail_view_invalid_private_key(self):
        """Assert that `change_view` works if DB contains a corrupted private key"""

        with open(TEST_FILES / "test.certificate", "r") as client_certificate_f, open(
            TEST_FILES / "invalid.certificate", "r"
        ) as key_f:
            certificate = Certificate.objects.create(
                label="Test certificate",
                type=CertificateTypes.key_pair,
                public_certificate=File(
                    client_certificate_f, name="invalid.certificate"
                ),
                private_key=File(key_f, name="test.key"),
            )

        CertificateAdmin(model=Certificate, admin_site=AdminSite())

        User.objects.create_superuser(username="admin", password="secret")
        client = Client()
        client.login(username="admin", password="secret")

        # check response
        url = reverse(
            "admin:simple_certmanager_certificate_change", args=(certificate.pk,)
        )

        response = client.get(url)

        self.assertEqual(response.status_code, 200)

        # no exception expected, hence no logs
