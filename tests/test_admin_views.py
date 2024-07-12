import unittest

from django.test import RequestFactory

import pytest
from OpenSSL import crypto

from simple_certmanager.admin_views import (
    CertificateSigningRequestInfoForm,
    GenerateCertificateView,
)
from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate


class GenerateCertificateViewTestCase(unittest.TestCase):
    def test_create_csr(self):
        view = GenerateCertificateView()
        common_name = "example.com"
        country = "US"
        state = "California"
        city = "San Francisco"
        organization = "Example Organization"
        organizational_unit = "IT"
        email_address = "admin@example.com"

        private_key, csr = view.create_csr(
            common_name=common_name,
            country=country,
            state=state,
            city=city,
            organization=organization,
            organizational_unit=organizational_unit,
            email_address=email_address,
        )

        # Verify private key
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
        self.assertIsInstance(key, crypto.PKey)
        self.assertEqual(key.bits(), 2048)

        # Verify CSR
        req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
        self.assertIsInstance(req, crypto.X509Req)
        self.assertEqual(req.get_subject().CN, common_name)
        self.assertEqual(req.get_subject().C, country)
        self.assertEqual(req.get_subject().ST, state)
        self.assertEqual(req.get_subject().L, city)
        self.assertEqual(req.get_subject().O, organization)
        self.assertEqual(req.get_subject().OU, organizational_unit)
        self.assertEqual(req.get_subject().emailAddress, email_address)


class GenerateCertificateFormTestCase(unittest.TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def tearDown(self) -> None:
        Certificate.objects.all().delete()
        return super().tearDown()

    @pytest.mark.django_db
    def test_form_valid(self):
        view = GenerateCertificateView()
        request = self.factory.post("/admin/simple_certmanager/certificate/generate/")
        form_data = {
            "country_name": "US",
            "organization_name": "Example Organization",
            "state_or_province_name": "California",
            "email_address": "admin@example.com",
            "common_name": "example.com",
        }
        form = CertificateSigningRequestInfoForm(data=form_data)
        request.POST = form_data
        request.method = "POST"
        request.user = None
        view.request = request

        if form.is_valid():
            response = view.form_valid(form)
        else:
            self.fail("Form is not valid")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/admin/simple_certmanager/certificate/")

        certificates = Certificate.objects.all()
        self.assertEqual(certificates.count(), 1)
        certificate = certificates.first()
        self.assertEqual(certificate.type, CertificateTypes.cert_only)
        self.assertEqual(certificate.info.country_name, "US")
        self.assertEqual(certificate.info.organization_name, "Example Organization")
        self.assertEqual(certificate.info.state_or_province_name, "California")
        self.assertEqual(certificate.info.email_address, "admin@example.com")
        self.assertEqual(certificate.info.common_name, "saml.example.com")

    @pytest.mark.django_db
    def test_save_certificate(self):
        view = GenerateCertificateView()
        certificate_info = {
            "country": "US",
            "organization": "Example Organization",
            "state": "California",
            "email_address": "a@a.com",
            "common_name": "example.com",
        }

        private_key, csr = view.create_csr(**certificate_info)

        view.save_certificate(certificate_info, private_key, csr)

        certificates = Certificate.objects.all()
        self.assertEqual(certificates.count(), 1)
        certificate = certificates.first()
        self.assertEqual(certificate.type, CertificateTypes.cert_only)
        self.assertEqual(certificate.info.country_name, "US")
        self.assertEqual(certificate.info.organization_name, "Example Organization")
        self.assertEqual(certificate.info.state_or_province_name, "California")
        self.assertEqual(certificate.info.email_address, "a@a.com")
        self.assertEqual(certificate.info.common_name, "example.com")
        # The saving method should not prepend "saml."
        # It is added in the form_valid method
        self.assertEqual(
            certificate.label, f"#{certificate.id} - Example Organization certificate"
        )
        self.assertFalse(
            certificate.public_certificate.name
        )  # Recommended way to check if the file field is empty
        self.assertIsNotNone(certificate.private_key)
