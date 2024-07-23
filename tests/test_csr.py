from django.contrib.admin.sites import AdminSite
from django.http import HttpResponse
from django.urls import reverse

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from simple_certmanager.admin import SigningRequestAdmin, download_csr
from simple_certmanager.models import SigningRequest


@pytest.fixture
def signing_request():
    return SigningRequest(common_name="test.com")


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

    signing_request = SigningRequest.objects.last()
    assert signing_request is not None
    assert signing_request.private_key != ""
    assert signing_request.csr != ""
    assert "BEGIN PRIVATE KEY" in signing_request.private_key


@pytest.mark.django_db
def test_save_generates_private_key_and_csr(signing_request):
    assert signing_request.private_key == ""
    assert signing_request.csr == ""
    signing_request.save()
    assert signing_request.private_key != ""
    assert signing_request.csr != ""


@pytest.mark.django_db
def test_generate_csr():
    signing_request = SigningRequest(
        common_name="test.com",
        country_name="US",
        organization_name="Test Org",
        state_or_province_name="Test State",
        email_address="test@test.com",
    )

    signing_request.generate_private_key()
    signing_request.save()

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


def test_generate_private_key():
    signing_request = SigningRequest(common_name="test.com")
    assert signing_request.private_key == ""
    signing_request.generate_private_key()
    assert signing_request.private_key != ""
    assert "BEGIN PRIVATE KEY" in signing_request.private_key


@pytest.mark.django_db
def test_download_csr_single():
    site = AdminSite()
    admin = SigningRequestAdmin(SigningRequest, site)
    request = None  # Simulate a Django request object
    signing_request = SigningRequest.objects.create(
        common_name="Test", csr="CSR Content"
    )
    queryset = SigningRequest.objects.filter(pk=signing_request.pk)

    response = download_csr(admin, request, queryset)

    assert isinstance(response, HttpResponse)
    assert response["Content-Type"] == "application/x-pem-file"
    assert "attachment; filename=" in response["Content-Disposition"]


@pytest.mark.django_db
def test_download_csr_multiple():
    site = AdminSite()
    admin = SigningRequestAdmin(SigningRequest, site)
    request = None
    signing_request1 = SigningRequest.objects.create(
        common_name="Test", csr="CSR Content"
    )
    signing_request2 = SigningRequest.objects.create(
        common_name="Test2", csr="CSR Content"
    )
    queryset = SigningRequest.objects.filter(
        pk__in=[signing_request1.pk, signing_request2.pk]
    )

    response = download_csr(admin, request, queryset)

    assert isinstance(response, HttpResponse)
    assert response["Content-Type"] == "application/zip"
    assert "attachment; filename=" in response["Content-Disposition"]
