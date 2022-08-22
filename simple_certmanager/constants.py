from django.utils.translation import gettext_lazy as _

from djchoices import ChoiceItem, DjangoChoices


class CertificateTypes(DjangoChoices):
    key_pair = ChoiceItem("key_pair", _("Key-pair"))
    cert_only = ChoiceItem("cert_only", _("Certificate only"))
