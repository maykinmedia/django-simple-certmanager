from datetime import datetime

from django.db import models
from django.utils.translation import gettext, gettext_lazy as _

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509 import (
    Certificate as CryptographyCertificate,
    load_pem_x509_certificate,
)
from privates.fields import PrivateMediaFileField

from simple_certmanager.csr_generation import generate_private_key_with_csr

from .constants import CertificateTypes
from .mixins import DeleteFileFieldFilesMixin
from .utils import load_pem_x509_private_key, pretty_print_certificate_components
from .validators import PrivateKeyValidator, PublicCertValidator


class SigningRequest(models.Model):
    common_name = models.CharField(
        max_length=100,
        help_text=_("The common name for the certificate"),
    )
    country_name = models.CharField(
        max_length=2, help_text=_("Two-letter country code"), blank=True, default="NL"
    )
    organization_name = models.CharField(
        max_length=100, help_text=_("The name of the organization"), blank=True
    )
    state_or_province_name = models.CharField(
        max_length=100, help_text=_("The state or province name"), blank=True
    )
    locality_name = models.CharField(
        max_length=100, help_text=_("The locality name"), blank=True
    )
    email_address = models.EmailField(
        help_text=_("Email address for the certificate"), blank=True
    )
    csr = models.TextField(
        editable=False,
        blank=True,
        help_text=_("Certificate Signing Request"),
        verbose_name=_("CSR"),
    )
    private_key = models.TextField(
        editable=False,
        blank=True,
    )

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=models.Q(
                    models.Q(csr="", private_key="")
                    | (~models.Q(csr="") & ~models.Q(private_key=""))
                ),
                name="csr_and_private_key_must_be_set_together",
            )
        ]

    def __str__(self):
        return _("Signing Request #{pk} for {common_name}").format(
            pk=self.pk,
            common_name=self.common_name,
        )

    def save(self, *args, **kwargs):
        # we generate private key + csr as one atomic unit
        if not self.private_key:
            self.private_key, self.csr = generate_private_key_with_csr(
                common_name=self.common_name,
                organization_name=self.organization_name,
                locality=self.locality_name,
                state_or_province=self.state_or_province_name,
                country=self.country_name,
                email=self.email_address,
            )
        super().save(*args, **kwargs)


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
