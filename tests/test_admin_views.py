import unittest

from OpenSSL import crypto

from simple_certmanager.admin_views import GenerateCertificateView


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
