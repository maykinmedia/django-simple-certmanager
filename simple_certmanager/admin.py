from io import BytesIO
from zipfile import ZipFile

from django.contrib import admin
from django.http import FileResponse, HttpResponseRedirect
from django.urls import reverse
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _

from privates.admin import PrivateMediaMixin

from .forms import CertificateAdminForm
from .models import Certificate, SigningRequest
from .utils import suppress_cryptography_errors


def download_csr(modeladmin, request, queryset):
    if (num := len(queryset)) > 1:
        zip_file = BytesIO()
        with ZipFile(zip_file, "w") as zipf:
            for csr in queryset:
                csr_content = csr.csr
                csr_filename = f"{slugify(csr.common_name)}_{csr.pk}_csr.pem"
                zipf.writestr(csr_filename, csr_content)
        zip_file.seek(0)
        return FileResponse(
            zip_file,
            as_attachment=True,
            filename="csr.zip",
        )
    elif num == 1:
        csr = queryset[0].csr
        return FileResponse(
            BytesIO(csr.encode()),
            as_attachment=True,
            filename=f"{slugify(queryset[0].common_name)}_{queryset[0].pk}_csr.pem",
        )
    else:
        modeladmin.message_user(
            request,
            _("No CSR selected."),
        )


@admin.register(SigningRequest)
class SigningRequestAdmin(admin.ModelAdmin):
    fieldsets = (
        (
            _("Subject information"),
            {
                "fields": (
                    "common_name",
                    "organization_name",
                    "country_name",
                    "state_or_province_name",
                    "email_address",
                ),
                "description": (
                    _("Fill in this information and click 'SAVE' to generate the CSR.")
                ),
            },
        ),
        (
            _("Certificate Signing Request Content"),
            {
                "fields": ("csr",),
            },
        ),
    )
    list_display = (
        "common_name",
        "organization_name",
        "country_name",
        "state_or_province_name",
        "email_address",
    )
    list_filter = ("organization_name", "state_or_province_name")
    search_fields = ("common_name", "organization_name")
    readonly_fields = ("csr",)
    actions = [download_csr]

    def response_add(self, request, obj, post_url_continue=None):
        return HttpResponseRedirect(
            reverse("admin:simple_certmanager_signingrequest_change", args=(obj.pk,))
        )


@admin.register(Certificate)
class CertificateAdmin(PrivateMediaMixin, admin.ModelAdmin):
    model: type[Certificate]
    form = CertificateAdminForm

    fields = (
        "label",
        "serial_number",
        "type",
        "public_certificate",
        "private_key",
        "private_key_passphrase",
    )
    list_display = (
        "get_label",
        "serial_number",
        "type",
        "valid_from",
        "expiry_date",
        "is_valid_key_pair",
    )
    list_filter = ("type",)
    search_fields = ("label", "type")
    readonly_fields = ("serial_number",)

    private_media_fields = ("public_certificate", "private_key")
    private_media_no_download_fields = ("private_key",)

    @admin.display(description=_("label"), ordering="label")
    def get_label(self, obj) -> str:
        return str(obj)

    @admin.display(description=_("serial number"))
    @suppress_cryptography_errors
    def serial_number(self, obj: Certificate):
        # alias model property to catch errors
        try:
            return obj.serial_number
        except FileNotFoundError:
            return _("file not found")

    @admin.display(description=_("valid from"))
    @suppress_cryptography_errors
    def valid_from(self, obj: Certificate):
        # alias model property to catch errors
        try:
            return obj.valid_from
        except FileNotFoundError:
            return _("file not found")

    @admin.display(description=_("expiry date"))
    @suppress_cryptography_errors
    def expiry_date(self, obj: Certificate):
        # alias model property to catch errors
        try:
            return obj.expiry_date
        except FileNotFoundError:
            return _("file not found")

    @admin.display(description=_("valid key pair"), boolean=True)
    @suppress_cryptography_errors
    def is_valid_key_pair(self, obj: Certificate) -> bool | None:
        # alias model property to catch errors
        try:
            return obj.is_valid_key_pair()
        except FileNotFoundError:
            return None
