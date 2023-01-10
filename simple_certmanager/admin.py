from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from privates.admin import PrivateMediaMixin

from .forms import CertificateAdminForm
from .models import Certificate
from .utils import suppress_crypto_errors


@admin.register(Certificate)
class CertificateAdmin(PrivateMediaMixin, admin.ModelAdmin):
    form = CertificateAdminForm

    fields = ("label", "serial_number", "type", "public_certificate", "private_key")
    list_display = (
        "get_label",
        "serial_number",
        "type",
        "expiry_date",
        "is_valid_key_pair",
        "has_valid_chain",
    )
    list_filter = ("label", "type")
    search_fields = ("label", "type")
    readonly_fields = ("serial_number",)

    private_media_fields = ("public_certificate", "private_key")
    private_media_no_download_fields = ("private_key",)

    @admin.display(description=_("label"), ordering="label")
    def get_label(self, obj):
        return str(obj)

    @admin.display(description=_("serial number"))
    @suppress_crypto_errors
    def serial_number(self, obj: Certificate):
        # alias model property to catch errors
        try:
            return obj.serial_number
        except FileNotFoundError:
            return _("file not found")

    @admin.display(description=_("expiry date"))
    @suppress_crypto_errors
    def expiry_date(self, obj: Certificate):
        # alias model property to catch errors
        try:
            return obj.expiry_date
        except FileNotFoundError:
            return _("file not found")

    @admin.display(description=_("valid key pair"), boolean=True)
    @suppress_crypto_errors
    def is_valid_key_pair(self, obj: Certificate):
        # alias model property to catch errors
        try:
            return obj.is_valid_key_pair()
        except FileNotFoundError:
            return None

    @admin.display(description=_("valid chain"), boolean=True)
    @suppress_crypto_errors
    def has_valid_chain(self, obj: Certificate):
        try:
            return obj.has_valid_chain()
        except FileNotFoundError:
            return None
