import logging
from pathlib import Path

from django.core.files import File
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

import pytest
from pyquery import PyQuery as pq

from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate

TEST_FILES = Path(__file__).parent / "data"


def test_list_view(temp_private_root, admin_client):
    """Assert that certificates are correctly displayed in the list view"""
    url = reverse("admin:simple_certmanager_certificate_changelist")
    with open(TEST_FILES / "test.certificate", "r") as client_certificate_f:
        certificate = Certificate.objects.create(
            label="Test certificate",
            type=CertificateTypes.key_pair,
            public_certificate=File(client_certificate_f, name="test.certificate"),
        )

    response = admin_client.get(url)

    assert response.status_code == 200

    # check that certificate is correctly displayed
    html = response.content.decode("utf-8")
    doc = pq(html)
    fields = doc(".field-get_label")
    anchor = fields[0].getchildren()[0]
    assert anchor.tag == "a"
    assert anchor.text == certificate.label


def test_detail_view(temp_private_root, admin_client):
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
    url = reverse("admin:simple_certmanager_certificate_change", args=(certificate.pk,))

    response = admin_client.get(url)

    assert response.status_code == 200

    # parse content
    html = response.content.decode("utf-8")
    doc = pq(html)
    uploads = doc(".file-upload")

    # check that public certificate is correctly displayed with link
    anchor = uploads.children()[0]

    assert anchor.tag == "a"
    assert anchor.text == certificate.public_certificate.name

    # check that private key is correctly displayed without link
    private_key = uploads[1]
    display_value = private_key.text.strip()
    assert private_key.tag == "p"
    assert display_value == _("Currently: %s") % certificate.private_key.name


def test_list_view_invalid_public_cert(temp_private_root, admin_client, caplog):
    """Assert that `changelist_view` works if DB contains a corrupted public cert"""
    url = reverse("admin:simple_certmanager_certificate_changelist")
    with open(TEST_FILES / "invalid.certificate", "r") as client_certificate_f:
        Certificate.objects.create(
            label="Test certificate",
            type=CertificateTypes.cert_only,
            public_certificate=File(client_certificate_f, name="invalid.certificate"),
        )
    caplog.set_level(logging.WARNING, logger="simple_certmanager.utils")

    response = admin_client.get(url)

    assert response.status_code == 200
    assert (
        caplog.records[0].message
        == "Suppressed exception while attempting to process PKI data"
    )
    assert caplog.records[0].levelname == "WARNING"


def test_list_view_invalid_private_key(temp_private_root, admin_client, caplog):
    """Assert that `changelist_view` works if DB contains a corrupted private key"""
    url = reverse("admin:simple_certmanager_certificate_changelist")
    with open(TEST_FILES / "test.certificate", "r") as client_certificate_f, open(
        TEST_FILES / "invalid.certificate", "r"
    ) as key_f:
        Certificate.objects.create(
            label="Test certificate",
            type=CertificateTypes.key_pair,
            public_certificate=File(client_certificate_f, name="invalid.certificate"),
            private_key=File(key_f, name="test.key"),
        )
    caplog.set_level(logging.WARNING, logger="simple_certmanager.utils")

    response = admin_client.get(url)

    assert response.status_code == 200
    assert (
        caplog.records[0].message
        == "Suppressed exception while attempting to process PKI data"
    )
    assert caplog.records[0].levelname == "WARNING"


@pytest.mark.xfail
def test_detail_view_invalid_public_cert(temp_private_root, admin_client, caplog):
    """Assert that `change_view` works if DB contains a corrupted public cert

    The test currently fails because the workaround for corrupted data only
    patches the admin and doesn't touch the models. This is not an immediate
    concern, but the test is kept in place for the purpose of documentation."""

    with open(TEST_FILES / "invalid.certificate", "r") as client_certificate_f:
        certificate = Certificate.objects.create(
            label="Test certificate",
            type=CertificateTypes.cert_only,
            public_certificate=File(client_certificate_f, name="invalid.certificate"),
        )
    url = reverse("admin:simple_certmanager_certificate_change", args=(certificate.pk,))
    caplog.set_level(logging.WARNING, logger="simple_certmanager.utils")

    response = admin_client.get(url)

    assert response.status_code == 200
    assert (
        caplog.records[0].message
        == "Suppressed exception while attempting to process PKI data"
    )
    assert caplog.records[0].levelname == "WARNING"


def test_detail_view_invalid_private_key(temp_private_root, admin_client, caplog):
    """Assert that `change_view` works if DB contains a corrupted private key"""

    with open(TEST_FILES / "test.certificate", "r") as client_certificate_f, open(
        TEST_FILES / "invalid.certificate", "r"
    ) as key_f:
        certificate = Certificate.objects.create(
            label="Test certificate",
            type=CertificateTypes.key_pair,
            public_certificate=File(client_certificate_f, name="invalid.certificate"),
            private_key=File(key_f, name="test.key"),
        )
    url = reverse("admin:simple_certmanager_certificate_change", args=(certificate.pk,))
    caplog.set_level(logging.WARNING, logger="simple_certmanager.utils")

    response = admin_client.get(url)

    assert response.status_code == 200
    assert caplog.records == []
