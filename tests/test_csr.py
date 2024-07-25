import zipfile
from io import BytesIO

from django.http import FileResponse
from django.urls import reverse

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from simple_certmanager.csr_generation import generate_private_key
from simple_certmanager.models import SigningRequest


@pytest.fixture
def signing_request():
    return SigningRequest(common_name="test.com")


@pytest.mark.django_db
def test_creating_signing_request_without_common_name_fails():
    with pytest.raises(Exception):
        SigningRequest.objects.create()


@pytest.mark.django_db
def test_admin_create_signing_request(admin_client, db):
    add_url = reverse("admin:simple_certmanager_signingrequest_add")

    data = {
        "common_name": "test.com",
        "country_name": "US",
        "organization_name": "Test Org",
        "state_or_province_name": "Test State",
        "email_address": "test@test.com",
    }

    response = admin_client.post(add_url, data, follow=True)

    assert response.status_code == 200

    signing_request = SigningRequest.objects.get()
    assert signing_request is not None
    assert signing_request.private_key != ""
    assert signing_request.csr != ""
    assert "BEGIN PRIVATE KEY" in signing_request.private_key


@pytest.mark.django_db
def test_save_generates_private_key_and_csr(signing_request):
    assert signing_request.private_key == ""
    assert signing_request.csr == ""
    signing_request.save()
    saved_private_key = signing_request.private_key
    assert signing_request.private_key != ""
    assert signing_request.csr != ""
    # Additional saves do not overwrite the private key
    signing_request.save()
    assert signing_request.private_key == saved_private_key


@pytest.mark.django_db
def test_generate_csr():
    signing_request = SigningRequest.objects.create(
        common_name="test.com",
        country_name="US",
        organization_name="Test Org",
        state_or_province_name="Test State",
        email_address="test@test.com",
    )

    csr = x509.load_pem_x509_csr(signing_request.csr.encode(), default_backend())

    subject = csr.subject
    assert subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value == "US"
    assert (
        subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "test.com"
    )
    assert (
        subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
        == "Test Org"
    )
    assert (
        subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME)[0].value
        == "Test State"
    )
    assert (
        subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)[0].value
        == "test@test.com"
    )


@pytest.mark.django_db
def test_generate_private_key():
    saved_private_key = generate_private_key()

    assert saved_private_key != ""
    assert "BEGIN PRIVATE KEY" in saved_private_key


@pytest.mark.django_db
def test_download_csr_single(admin_client):
    signing_request = SigningRequest.objects.create(
        common_name="Test", country_name="NL"
    )

    url = reverse("admin:simple_certmanager_signingrequest_changelist")
    response = admin_client.post(
        url, {"action": "download_csr", "_selected_action": [signing_request.pk]}
    )

    assert isinstance(response, FileResponse)
    assert response["Content-Type"] == "application/pem-certificate-chain"
    assert "attachment; filename=" in response["Content-Disposition"]

    # Load the CSR and assert the attributes
    csr_content = BytesIO(b"".join(response.streaming_content))
    csr = x509.load_pem_x509_csr(csr_content.read(), default_backend())
    assert (
        csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "Test"
    )
    assert (
        csr.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value == "NL"
    )


@pytest.mark.django_db
def test_download_csr_multiple(admin_client):
    signing_request1 = SigningRequest.objects.create(
        common_name="test.com", country_name="NL"
    )
    signing_request2 = SigningRequest.objects.create(
        common_name="test2.com", country_name="FR"
    )

    url = reverse("admin:simple_certmanager_signingrequest_changelist")
    response = admin_client.post(
        url,
        {
            "action": "download_csr",
            "_selected_action": [signing_request1.pk, signing_request2.pk],
        },
    )

    assert isinstance(response, FileResponse)
    assert response["Content-Type"] == "application/zip"
    assert "attachment; filename=" in response["Content-Disposition"]

    # Extract the zip file
    response_content = BytesIO(b"".join(response.streaming_content))
    with zipfile.ZipFile(response_content, "r") as zip_file:
        csr_files = zip_file.namelist()
        assert len(csr_files) == 2

        # Load and assert the content of each CSR file
        for csr_file in csr_files:
            csr_content = zip_file.read(csr_file)
            csr = x509.load_pem_x509_csr(csr_content, default_backend())
            assert csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
                0
            ].value in ["test.com", "test2.com"]
            assert csr.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[
                0
            ].value in ["NL", "FR"]