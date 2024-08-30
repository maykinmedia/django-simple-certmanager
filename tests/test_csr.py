import zipfile
from io import BytesIO

from django.contrib.messages import get_messages
from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import FileResponse
from django.urls import reverse

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from simple_certmanager.csr_generation import generate_csr, generate_private_key
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

    assert signing_request.private_key != ""
    assert signing_request.csr != ""
    assert "BEGIN PRIVATE KEY" in signing_request.private_key


@pytest.mark.django_db
def test_save_generates_private_key(signing_request):
    assert signing_request.private_key == ""
    signing_request.save()
    saved_private_key = signing_request.private_key
    assert signing_request.private_key != ""
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

    csr = x509.load_pem_x509_csr(signing_request.csr.encode("ascii"), default_backend())

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
        url, {"action": "download_csr_action", "_selected_action": [signing_request.pk]}
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
            "action": "download_csr_action",
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

    private_key = load_pem_x509_private_key(csr.private_key.encode("ascii"))
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

    cert_pem.seek(0)

    # Saving the same certificate is not possible anymore
    # We removed the permission when the SigningRequest was signed
    response = admin_client.post(
        f"/admin/simple_certmanager/signingrequest/{csr.pk}/change/",
        data=form_data,
    )
    assert response.status_code == 403


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
    private_key = load_pem_x509_private_key(private_key.encode("ascii"))
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
        "Invalid file provided, expected a certificate in PEM format"
    ]
    assert Certificate.objects.count() == 0


def test_csr_is_a_function_of_private_key_plus_subject_fields():
    "Generated CSR only changes depending on key and subject"
    my_private_key_pem = generate_private_key()
    csr_once = generate_csr(key_pem=my_private_key_pem, common_name="Foo")
    csr_twice = generate_csr(key_pem=my_private_key_pem, common_name="Foo")
    assert csr_once == csr_twice


@pytest.mark.django_db
def test_csr_does_not_change_if_subject_dont_change(admin_client):
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
        },
    )

    assert response.status_code == 302
    signing_request.refresh_from_db()
    # PK should not have changed
    assert signing_request.private_key == original_pk
    # CSR should not have changed since suject and pk are the same
    assert signing_request.csr == orginal_csr


@pytest.mark.django_db
def test_csr_renews_if_subject_changes(admin_client):
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
            "common_name": "test.fr",
            "country_name": "FR",
            "organization_name": "Test Org",
            "state_or_province_name": "Test State",
            "email_address": "test@test.com",
        },
    )

    assert response.status_code == 302
    signing_request.refresh_from_db()
    # PK should not have changed
    assert signing_request.private_key == original_pk
    # CSR should have changed since suject has changed
    assert signing_request.csr != original_csr


@pytest.mark.django_db
def test_saving_public_certifate_disables_signing_request_fields(admin_client):
    assert Certificate.objects.count() == 0

    csr = SigningRequest.objects.create(
        common_name="test.example.com",
        organization_name="Test Organization",
        state_or_province_name="Test State",
        country_name="NL",
        email_address="email@valid.com",
    )

    private_key = load_pem_x509_private_key(csr.private_key.encode("ascii"))
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
    response = admin_client.get(
        f"/admin/simple_certmanager/signingrequest/{csr.pk}/change/"
    )
    assert response.status_code == 200
    # Check that the fields are readonly
    # 9 readonly fields in the form
    # csr, public_certificate, common_name, organization_name, country_name,
    # state_or_province_name, locality_name, email_address, certificate
    assert response.content.decode().count("readonly") == 9


@pytest.mark.django_db
def test_csr_creation_and_display(admin_client):
    add_url = reverse("admin:simple_certmanager_signingrequest_add")

    response = admin_client.get(add_url)
    assert response.status_code == 200
    assert (
        "Save the signing request to be able to download it."
        in response.content.decode()
    )

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
    assert signing_request.private_key != ""
    assert signing_request.csr != ""
    assert "BEGIN PRIVATE KEY" in signing_request.private_key
    assert "Download CSR" in response.content.decode()

    # Download CSR logged in as admin
    download_csr_url = reverse("admin:download_csr", args=(signing_request.pk,))
    response = admin_client.get(download_csr_url)
    assert response.status_code == 200


def test_csr_download_permission(client, django_user_model):
    signing_request = SigningRequest.objects.create(
        common_name="test.com",
        country_name="US",
        organization_name="Test Org",
        state_or_province_name="Test State",
        email_address="test@test.com",
    )

    # User without permission to add SigningRequests can't download CSR
    user = django_user_model.objects.create_user(
        username="test", password="test", is_staff=True
    )
    # Permissions
    can_add = user.has_perm("simple_certmanager.add_signingrequest")
    can_change = user.has_perm("simple_certmanager.change_signingrequest")
    can_delete = user.has_perm("simple_certmanager.delete_signingrequest")
    can_view = user.has_perm("simple_certmanager.view_signingrequest")

    # Assertions to check user permissions
    assert not can_add, "User should not have permission to add SigningRequest"
    assert not can_change, "User should not have permission to change SigningRequest"
    assert not can_delete, "User should not have permission to delete SigningRequest"
    assert not can_view, "User should not have permission to view SigningRequest"

    client.force_login(user)

    download_csr_url = reverse("admin:download_csr", args=(signing_request.pk,))
    response = client.get(download_csr_url)

    url = "/admin/simple_certmanager/signingrequest/"
    assert response.status_code == 302
    assert response.url == url

    messages = list(get_messages(response.wsgi_request))
    assert len(messages) == 1
    assert str(messages[0]) == "You do not have permission to download this CSR."
