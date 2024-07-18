import logging
from io import BytesIO
from pathlib import Path

from django.core.files import File
from django.test import Client
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from pyquery import PyQuery as pq
from pytest_django.asserts import assertContains

from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate
from simple_certmanager.utils import decrypted_key_to_pem

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
    with (
        open(TEST_FILES / "test.certificate", "r") as client_certificate_f,
        open(TEST_FILES / "test.key", "r") as key_f,
    ):
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
    with (
        open(TEST_FILES / "test.certificate", "r") as client_certificate_f,
        open(TEST_FILES / "invalid.certificate", "r") as key_f,
    ):
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

    with (
        open(TEST_FILES / "test.certificate", "r") as client_certificate_f,
        open(TEST_FILES / "invalid.certificate", "r") as key_f,
    ):
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


def test_upload_keypair_with_encrypted_key(
    admin_client: Client, encrypted_keypair: tuple[bytes, bytes]
):
    url = reverse("admin:simple_certmanager_certificate_add")
    key, cert = encrypted_keypair

    response = admin_client.post(
        url,
        {
            "label": "Encrypted key",
            "type": CertificateTypes.key_pair,
            "private_key": BytesIO(key),
            "public_certificate": BytesIO(cert),
            "private_key_passphrase": "SUPERSECRET🔐",
        },
    )

    assert response.status_code == 302  # redirects back to list

    # check that the key is decrypted in the created object
    certificate = Certificate.objects.get()
    assert not hasattr(certificate, "key_passphrase")  # not a model field!
    with certificate.private_key.open("rb") as key_file:
        try:
            # we should be able to load the private key without password now
            load_pem_private_key(key_file.read(), password=None)
        except Exception:
            pytest.fail("Expected the key to be stored unencrypted")


def test_upload_keypair_with_encrypted_key_without_passphrase(
    admin_client: Client, encrypted_keypair: tuple[bytes, bytes]
):
    url = reverse("admin:simple_certmanager_certificate_add")
    key, cert = encrypted_keypair

    response = admin_client.post(
        url,
        {
            "label": "Encrypted key",
            "type": CertificateTypes.key_pair,
            "private_key": BytesIO(key),
            "public_certificate": BytesIO(cert),
            "private_key_passphrase": "",
        },
    )

    assert response.status_code == 200  # validation errors
    assertContains(
        response,
        _("Provide a passphrase to decrypt the private key."),
    )


def test_upload_keypair_with_encrypted_key_wrong_passphrase(
    admin_client: Client, encrypted_keypair: tuple[bytes, bytes]
):
    url = reverse("admin:simple_certmanager_certificate_add")
    key, cert = encrypted_keypair

    response = admin_client.post(
        url,
        {
            "label": "Encrypted key",
            "type": CertificateTypes.key_pair,
            "private_key": BytesIO(key),
            "public_certificate": BytesIO(cert),
            "private_key_passphrase": "letmein",
        },
    )

    assert response.status_code == 200  # validation errors
    assertContains(
        response,
        _("Could not decrypt the private key with the provided passphrase."),
    )


def test_upload_keypair_not_encrypted_with_passphrase(
    admin_client: Client,
    leaf_keypair: tuple[rsa.RSAPrivateKey, bytes],
):
    url = reverse("admin:simple_certmanager_certificate_add")
    _key, cert = leaf_keypair
    key = decrypted_key_to_pem(_key)

    response = admin_client.post(
        url,
        {
            "label": "Encrypted key",
            "type": CertificateTypes.key_pair,
            "private_key": BytesIO(key),
            "public_certificate": BytesIO(cert),
            "private_key_passphrase": "letmein",
        },
    )

    assert response.status_code == 200  # validation errors
    assertContains(
        response,
        _("The private key is not encrypted, a passphrase is not required."),
    )
