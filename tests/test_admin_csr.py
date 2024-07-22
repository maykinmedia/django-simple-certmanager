import datetime
from pathlib import Path

from django.contrib import admin
from django.contrib.admin.sites import AdminSite
from django.core.files import File
from django.core.files.base import ContentFile
from django.http import HttpResponse
from django.urls import reverse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyquery import PyQuery as pq

from simple_certmanager.admin import SigningRequestAdmin, download_csr
from simple_certmanager.forms import SigningRequestAdminForm
from simple_certmanager.models import Certificate, SigningRequest
from tests.conftest import mkcert

TEST_FILES = Path(__file__).parent / "data"


def test_csr_list_view(temp_private_root, admin_client):
    """Assert that certificate signing requests
    are correctly displayed in the list view"""
    url = reverse("admin:simple_certmanager_signingrequest_changelist")
    with open(TEST_FILES / "csr.pem", "r") as csr_f:
        csr = SigningRequest.objects.create(
            common_name="test.example.com",
            organization_name="Test Organization",
            state_or_province_name="Test State",
            csr=File(csr_f, name="test.csr"),
        )

    response = admin_client.get(url)

    assert response.status_code == 200

    # check that CSR is correctly displayed
    html = response.content.decode("utf-8")
    doc = pq(html)
    fields = doc(".field-common_name")
    anchor = fields[0].getchildren()[0]
    assert anchor.tag == "a"
    assert anchor.text == csr.common_name


def test_csr_detail_view(temp_private_root, admin_client):
    """Assert that CSRs are correctly displayed in the Admin's change_view"""
    csr = SigningRequest.objects.create(
        common_name="test.example.com",
        organization_name="Test Organization",
        state_or_province_name="Test State",
        country_name="NL",
        email_address="email@valid.com",
    )
    url = reverse("admin:simple_certmanager_signingrequest_change", args=(csr.pk,))

    response = admin_client.get(url)

    assert response.status_code == 200

    # parse content
    html = response.content.decode("utf-8")
    doc = pq(html)
    csr_div = doc(".readonly")

    # check that the CSR has been generated
    assert csr_div[0].text == "-----BEGIN CERTIFICATE REQUEST-----"

    # check that the private key is present
    uploads = doc(".file-upload")

    assert len(uploads) == 1
    current_date = datetime.date.today().strftime("%Y/%m/%d")
    assert (
        uploads[0].text.strip()
        == f"Currently: ssl_certs_keys/{current_date}/private_key.pem"
    )


def test_adding_csr_generates_CSR_and_PK(temp_private_root, admin_client):
    """Assert that CSRs are correctly displayed in the Admin's change_view"""
    assert Certificate.objects.count() == 0

    csr = SigningRequest.objects.create(
        common_name="test.example.com",
        organization_name="Test Organization",
        state_or_province_name="Test State",
        country_name="NL",
        email_address="email@valid.com",
    )
    url = reverse("admin:simple_certmanager_signingrequest_change", args=(csr.pk,))

    response = admin_client.get(url)

    assert response.status_code == 200

    # parse content
    html = response.content.decode("utf-8")
    doc = pq(html)
    csr_div = doc(".readonly")

    # check that the CSR has been generated
    assert csr_div[0].text == "-----BEGIN CERTIFICATE REQUEST-----"

    # check that the private key is present
    uploads = doc(".file-upload")

    assert len(uploads) == 1
    current_date = datetime.date.today().strftime("%Y/%m/%d")
    assert (
        uploads[0].text.strip()
        == f"Currently: ssl_certs_keys/{current_date}/private_key.pem"
    )


def test_saving_invalid_cert_doesnt_create_cert_instance(
    temp_private_root, admin_client
):
    """Assert that the save_model method creates a certificate object
    if the form includes an invalid certificate"""
    csr = SigningRequest.objects.create(
        common_name="test.example.com",
        organization_name="Test Organization",
        state_or_province_name="Test State",
        country_name="NL",
        email_address="email@valid.com",
    )
    invalid_cert_pem = ContentFile("invalid_bytes", "cert.pem")
    form_data = {
        "common_name": "test.example.com",
        "organization_name": "Test Organization",
        "country_name": "NL",
        "state_or_province_name": "Test State",
        "email_address": "email@valid.com",
    }
    form = SigningRequestAdminForm(
        instance=csr, data=form_data, files={"certificate": invalid_cert_pem}
    )
    assert not form.is_valid()

    model_admin = SigningRequestAdmin(SigningRequest, admin.site)
    model_admin.save_model(admin_client, csr, form, change=False)

    # Assert that a certificate object is NOT created
    assert Certificate.objects.count() == 0


def test_saving_valid_cert_does_create_cert_instance(admin_client, root_cert):
    """Assert that the save_model method creates a certificate object
    if the form includes a valid certificate"""
    csr = SigningRequest.objects.create(
        common_name="test.example.com",
        organization_name="Test Organization",
        state_or_province_name="Test State",
        country_name="NL",
        email_address="email@valid.com",
    )
    pub_cert = mkcert(
        subject=x509.Name(
            [
                x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "NL"),
                x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "NH"),
                x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, "Amsterdam"),
                x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Root CA"),
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "rootca.example.org"),
            ]
        ),
        subject_key=csr._private_key,
    )
    cert_bytes = pub_cert.public_bytes(serialization.Encoding.PEM)
    cert_pem = ContentFile(cert_bytes, "cert.pem")
    form_data = {
        "common_name": "test.example.com",
        "organization_name": "Test Organization",
        "country_name": "NL",
        "state_or_province_name": "Test State",
        "email_address": "email@valid.com",
    }
    form = SigningRequestAdminForm(
        instance=csr, data=form_data, files={"certificate": cert_pem}
    )
    assert form.is_valid()

    model_admin = SigningRequestAdmin(SigningRequest, admin.site)
    model_admin.save_model(admin_client, csr, form, change=False)

    # Assert that a certificate object is created
    assert Certificate.objects.count() == 1


def test_saving_valid_cert_does_create_cert_instance_via_post(
    admin_client,
    temp_private_root,
):
    csr = SigningRequest.objects.create(
        common_name="test.example.com",
        organization_name="Test Organization",
        state_or_province_name="Test State",
        country_name="NL",
        email_address="email@valid.com",
    )
    pub_cert = mkcert(
        subject=x509.Name(
            [
                x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "NL"),
                x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "NH"),
                x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, "Amsterdam"),
                x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Root CA"),
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "rootca.example.org"),
            ]
        ),
        subject_key=csr._private_key,
    )
    cert_bytes = pub_cert.public_bytes(serialization.Encoding.PEM)
    cert_pem = ContentFile(cert_bytes, "cert.pem")
    form_data = {
        "common_name": "test.example.com",
        "organization_name": "Test Organization",
        "country_name": "NL",
        "state_or_province_name": "Test State",
        "email_address": "email@valid.com",
    }

    response = admin_client.post(
        "/admin/simple_certmanager/signingrequest/add/",
        files={"certificate": cert_pem},
        data=form_data,
    )
    print(response.content.decode("utf-8"))

    assert Certificate.objects.count() == 1


@pytest.mark.django_db
def test_download_csr_single(signing_request_factory):
    site = AdminSite()
    admin = SigningRequestAdmin(SigningRequest, site)
    request = None  # Simulate a Django request object
    signing_request = signing_request_factory(common_name="Test", csr="CSR Content")
    queryset = SigningRequest.objects.filter(pk=signing_request.pk)

    response = download_csr(admin, request, queryset)

    assert isinstance(response, HttpResponse)
    assert response["Content-Type"] == "application/x-pem-file"
    assert "attachment; filename=" in response["Content-Disposition"]


@pytest.mark.django_db
def test_download_csr_multiple(signing_request_factory):
    site = AdminSite()
    admin = SigningRequestAdmin(SigningRequest, site)
    request = None
    signing_request1 = signing_request_factory(common_name="Test1", csr="CSR Content")
    signing_request2 = signing_request_factory(common_name="Test2", csr="CSR Content")
    queryset = SigningRequest.objects.filter(
        pk__in=[signing_request1.pk, signing_request2.pk]
    )

    response = download_csr(admin, request, queryset)

    assert isinstance(response, HttpResponse)
    assert response["Content-Type"] == "application/zip"
    assert "attachment; filename=" in response["Content-Disposition"]
