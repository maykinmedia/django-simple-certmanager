import zipfile
from io import BytesIO

from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import FileResponse
from django.urls import reverse

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from simple_certmanager.csr_generation import generate_private_key
from simple_certmanager.models import Certificate, SigningRequest
from simple_certmanager.test.certificate_generation import mkcert
from simple_certmanager.utils import load_pem_x509_private_key


@pytest.fixture
def signing_request():
    return SigningRequest(common_name="test.com")


@pytest.mark.django_db
def test_creating_signing_request_without_common_name_fails():
    with pytest.raises(Exception):
        SigningRequest.objects.create()


@pytest.mark.django_db
def test_admin_can_load_add_page(admin_client):
    add_url = reverse("admin:simple_certmanager_signingrequest_add")

    response = admin_client.get(add_url)

    assert response.status_code == 200


@pytest.mark.django_db
def test_admin_create_signing_request(admin_client):
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


@pytest.mark.django_db
def test_admin_save_existing_csr_should_renew(admin_client):
    signing_request = SigningRequest.objects.create(
        common_name="test.com",
        country_name="US",
        organization_name="Test Org",
        state_or_province_name="Test State",
        email_address="test@test.com",
    )

    orginal_csr = signing_request.csr
    original_pk = signing_request.private_key

    url = reverse(
        "admin:simple_certmanager_signingrequest_change", args=[signing_request.pk]
    )
    response = admin_client.post(
        url,
        {
            "common_name": "test.com",
            "country_name": "US",
            "organization_name": "Test Org",
            "state_or_province_name": "Test State",
            "email_address": "test@test.com",
            "should_renew_csr": True,
        },
    )

    assert response.status_code == 302
    signing_request.refresh_from_db()
    # CSR and PK should be regenerated
    assert signing_request.csr != orginal_csr
    assert signing_request.private_key != original_pk


@pytest.mark.django_db
def test_admin_save_existing_csr_should_not_renew(admin_client):
    signing_request = SigningRequest.objects.create(
        common_name="test.com",
        country_name="US",
        organization_name="Test Org",
        state_or_province_name="Test State",
        email_address="test@test.com",
    )

    original_csr = signing_request.csr
    original_pk = signing_request.private_key

    url = reverse(
        "admin:simple_certmanager_signingrequest_change", args=[signing_request.pk]
    )
    response = admin_client.post(
        url,
        {
            "common_name": "test.com",
            "country_name": "US",
            "organization_name": "Test Org",
            "state_or_province_name": "Test State",
            "email_address": "test@test.com",
            "should_renew_csr": False,
        },
    )

    assert response.status_code == 302
    signing_request.refresh_from_db()
    # CSR and PK should not be regenerated
    assert signing_request.csr == original_csr
    assert signing_request.private_key == original_pk


@pytest.mark.django_db
def test_saving_valid_cert_does_create_cert_instance_via_post(
    admin_client,
    temp_private_root,
):
    assert Certificate.objects.count() == 0

    csr = SigningRequest.objects.create(
        common_name="test.example.com",
        organization_name="Test Organization",
        state_or_province_name="Test State",
        country_name="NL",
        email_address="email@valid.com",
    )

    private_key = load_pem_x509_private_key(csr.private_key.encode())
    pub_cert = mkcert(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.example.com")]),
        private_key,
    )

    cert_bytes = pub_cert.public_bytes(serialization.Encoding.PEM)
    cert_pem = SimpleUploadedFile("cert.pem", cert_bytes)

    form_data = {
        "common_name": "test.example.com",
        "organization_name": "Test Organization",
        "country_name": "NL",
        "state_or_province_name": "Test State",
        "email_address": "email@valid.com",
        "certificate": cert_pem,
    }

    # Valid certificate should create a Certificate instance
    assert pub_cert.public_key() == private_key.public_key()

    response = admin_client.post(
        f"/admin/simple_certmanager/signingrequest/{csr.pk}/change/",
        data=form_data,
    )

    assert response.status_code == 302
    assert Certificate.objects.count() == 1

    # Saving the same certificate again should not create a new instance
    response = admin_client.post(
        f"/admin/simple_certmanager/signingrequest/{csr.pk}/change/",
        data=form_data,
    )
    assert response.status_code == 200
    assert len(response.context["adminform"].form.errors) > 0
    assert (
        "A certificate already exists for this CSR. Delete the certificate first."
        in response.context["adminform"].form.errors["certificate"]
    )
    assert Certificate.objects.count() == 1


@pytest.mark.django_db
def test_saving_valid_cert_with_invalid_signature_via_post_fails(
    admin_client,
    temp_private_root,
):
    assert Certificate.objects.count() == 0

    csr = SigningRequest.objects.create(
        common_name="test.example.com",
        organization_name="Test Organization",
        state_or_province_name="Test State",
        country_name="NL",
        email_address="email@valid.com",
    )

    # Use a different private key to generate the certificate with an invalid signature
    private_key = generate_private_key()
    private_key = load_pem_x509_private_key(private_key.encode())
    pub_cert = mkcert(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.example.com")]),
        private_key,
    )

    cert_bytes = pub_cert.public_bytes(serialization.Encoding.PEM)
    cert_pem = SimpleUploadedFile("cert.pem", cert_bytes)

    form_data = {
        "common_name": "test.example.com",
        "organization_name": "Test Organization",
        "country_name": "NL",
        "state_or_province_name": "Test State",
        "email_address": "email@valid.com",
        "certificate": cert_pem,
    }

    # Valid certificate should create a Certificate instance
    assert pub_cert.public_key() == private_key.public_key()

    # Saving the same certificate again should not create a new instance
    response = admin_client.post(
        f"/admin/simple_certmanager/signingrequest/{csr.pk}/change/",
        data=form_data,
    )
    assert response.status_code == 200
    assert len(response.context["adminform"].form.errors) > 0
    assert (
        "Certificate does not match the signature from the actual CSR."
        in response.context["adminform"].form.errors["certificate"]
    )
    assert Certificate.objects.count() == 0


@pytest.mark.django_db
def test_saving_invalid_cert_does_not_create_cert_instance_via_post(
    admin_client,
    temp_private_root,
):
    assert Certificate.objects.count() == 0

    csr = SigningRequest.objects.create(
        common_name="test.example.com",
        organization_name="Test Organization",
        state_or_province_name="Test State",
        country_name="NL",
        email_address="email@valid.com",
    )

    cert_pem = SimpleUploadedFile("cert.pem", b"invalid bytes")
    form_data = {
        "common_name": "test.example.com",
        "organization_name": "Test Organization",
        "country_name": "NL",
        "state_or_province_name": "Test State",
        "email_address": "email@valid.com",
        "certificate": cert_pem,
    }

    response = admin_client.post(
        f"/admin/simple_certmanager/signingrequest/{csr.pk}/change/",
        data=form_data,
    )

    assert response.status_code == 200
    assert len(response.context["adminform"].form.errors) > 0
    assert response.context["adminform"].form.errors["certificate"] == [
        "Invalid certificate. Check the file format."
    ]
    assert Certificate.objects.count() == 0
