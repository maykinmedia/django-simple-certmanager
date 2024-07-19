from datetime import datetime

from django.db import models
from django.utils.translation import gettext, gettext_lazy as _

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509 import (
    Certificate as CryptographyCertificate,
    load_pem_x509_certificate,
)
from privates.fields import PrivateMediaFileField

from .constants import CertificateTypes
from .mixins import DeleteFileFieldFilesMixin
from .utils import load_pem_x509_private_key, pretty_print_certificate_components
from .validators import PrivateKeyValidator, PublicCertValidator


class Certificate(DeleteFileFieldFilesMixin, models.Model):
    label = models.CharField(
        _("label"),
        max_length=100,
        help_text=_("Recognisable label for the certificate"),
    )
    type = models.CharField(
        _("type"),
        max_length=20,
        choices=CertificateTypes.choices,
        help_text=_(
            "Is this only a certificate or is there an associated private key?"
        ),
    )
    public_certificate = PrivateMediaFileField(
        _("public certificate"),
        help_text=_("The content of the certificate"),
        upload_to="ssl_certs_keys/%Y/%m/%d",
        validators=[PublicCertValidator()],
    )
    private_key = PrivateMediaFileField(
        _("private key"),
        help_text=_("The content of the private key"),
        blank=True,
        upload_to="ssl_certs_keys/%Y/%m/%d",
        validators=[PrivateKeyValidator()],
    )

    _certificate_obj: CryptographyCertificate | None = None
    _private_key_obj: PrivateKeyTypes | None = None

    class Meta:
        verbose_name = _("certificate")
        verbose_name_plural = _("certificates")

    def __str__(self) -> str:
        return self.label or gettext("(missing label)")

    @property
    def certificate(self) -> CryptographyCertificate:
        """
        Load and return the x509 certificate.

        :raises ValueError: if no certificate file is associated with the instance or
          if the certificate could not be loaded by ``cryptography``.
        """
        if self._certificate_obj is None:
            with self.public_certificate.open(mode="rb") as certificate_f:
                self._certificate_obj = load_pem_x509_certificate(certificate_f.read())
        return self._certificate_obj

    @property
    def _private_key(self):
        if self._private_key_obj is None:
            with self.private_key.open(mode="rb") as key_f:
                self._private_key_obj = load_pem_x509_private_key(key_f.read())
        return self._private_key_obj

    @property
    def valid_from(self) -> datetime:
        # TODO: should probably be stored in a DB column after saving the file so
        # we can query on it to report (nearly) expired certificates.
        return self.certificate.not_valid_before_utc

    @property
    def expiry_date(self) -> datetime:
        # TODO: should probably be stored in a DB column after saving the file so
        # we can query on it to report (nearly) expired certificates.
        return self.certificate.not_valid_after_utc

    @property
    def issuer(self) -> str:
        return pretty_print_certificate_components(self.certificate.issuer)

    @property
    def subject(self) -> str:
        return pretty_print_certificate_components(self.certificate.subject)

    @property
    def serial_number(self) -> str:
        x509sn = self.certificate.serial_number
        sn = hex(x509sn)[2:].upper()
        bytes = (sn[i : i + 2] for i in range(0, len(sn), 2))
        return ":".join(bytes)

    def is_valid_key_pair(self) -> None | bool:
        if not self.private_key:
            return None

        key_pubkey = self._private_key.public_key()
        cert_pubkey = self.certificate.public_key()
        return key_pubkey == cert_pubkey

    is_valid_key_pair.boolean = True  # type: ignore
