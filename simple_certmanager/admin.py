
from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from privates.admin import PrivateMediaMixin

from .forms import CertificateAdminForm
from .models import Certificate


@admin.register(Certificate)
class CertificateAdmin(PrivateMediaMixin, admin.ModelAdmin):
    form = CertificateAdminForm

    fields = ("label", "type", "public_certificate", "private_key")
    list_display = ("get_label", "type", "expiry_date", "is_valid_key_pair")
    list_filter = ("label", "type")
    search_fields = ("label", "type")

    private_media_fields = ("public_certificate", "private_key")

    def get_label(self, obj):
        return str(obj)

    get_label.short_description = _("label")
    get_label.admin_order_field = "label"

    def expiry_date(self, obj=None):
        # alias model property to catch file not found errors
        try:
            return obj.expiry_date
        except FileNotFoundError:
            return _("file not found")

    expiry_date.short_description = _("expiry date")

    def is_valid_key_pair(self, obj=None):
        # alias model method to catch file not found errors
        try:
            return obj.is_valid_key_pair()
        except FileNotFoundError:
            return None

    is_valid_key_pair.short_description = _("valid key pair")
    is_valid_key_pair.boolean = True
