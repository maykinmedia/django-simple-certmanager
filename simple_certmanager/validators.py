from django.core.exceptions import ValidationError
from django.core.files import File
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _

from cryptography.x509 import load_pem_x509_certificate

from .utils import KeyIsEncrypted, load_pem_x509_private_key


@deconstructible
class PKIValidatorBase:
    message = _("Invalid file provided")
    code = "invalid_pem"

    def validate(self, file_content: bytes) -> None:  # pragma: no cover
        """
        Given the binary content of the (uploaded) file, validate it.

        :raises ValueError: when the file content does not match the expected format.
        """
        raise NotImplementedError

    def __call__(self, value: File):
        if value.closed:
            # no context manager; Django takes care of closing the file
            value.open()
        try:
            self.validate(value.read())
        except ValueError:
            raise ValidationError(self.message, code=self.code)


class PublicCertValidator(PKIValidatorBase):
    message = _("Invalid file provided, expected a certificate in PEM format")

    def validate(self, file_content: bytes) -> None:
        load_pem_x509_certificate(file_content)


class PrivateKeyValidator(PKIValidatorBase):
    message = _("Invalid file provided, expected a private key in PEM format")

    def __init__(self, allow_encrypted: bool = False):
        self.allow_encrypted = allow_encrypted

    def validate(self, file_content: bytes) -> None:
        try:
            load_pem_x509_private_key(file_content, password=None)
        except KeyIsEncrypted:
            # we may need to allow encrypted private keys at this stage, the form
            # validation needs to check that a passphrase is provided that can decrypt
            # it.
            if not self.allow_encrypted:
                raise ValidationError(
                    _("Private key may not be encrypted."), code="encrypted_private_key"
                )
