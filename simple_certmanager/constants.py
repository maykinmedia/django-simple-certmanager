from django.db import models
from django.utils.translation import gettext_lazy as _


class CertificateTypes(models.TextChoices):
    key_pair = "key_pair", _("Key-pair")
    cert_only = "cert_only", _("Certificate only")
