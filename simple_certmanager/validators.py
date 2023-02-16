from django.core.exceptions import ValidationError
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _

from OpenSSL import crypto


@deconstructible
class PKIValidatorBase:
    message = _("Invalid file provided")
    code = "invalid_pem"

    @staticmethod
    def validate(file_content: bytes):  # pragma: no cover
        raise NotImplementedError

    def __call__(self, value):
        if value.closed:
            # no context manager; Django takes care of closing the file
            value.open()
        try:
            self.validate(value.read())
        except crypto.Error:
            raise ValidationError(self.message, code=self.code)


class PublicCertValidator(PKIValidatorBase):
    message = _("Invalid file provided, expected a certificate in PEM format")

    @staticmethod
    def validate(file_content: bytes):
        return crypto.load_certificate(crypto.FILETYPE_PEM, file_content)


class PrivateKeyValidator(PKIValidatorBase):
    message = _("Invalid file provided, expected a private key in PEM format")

    @staticmethod
    def validate(file_content: bytes):
        return crypto.load_privatekey(crypto.FILETYPE_PEM, file_content)
