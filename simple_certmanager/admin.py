from io import BytesIO
from zipfile import ZipFile

from django.contrib import admin
from django.http import FileResponse, HttpResponseRedirect
from django.urls import reverse
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _

from privates.admin import PrivateMediaMixin

from .forms import CertificateAdminForm, SigningRequestAdminForm
from .models import Certificate, SigningRequest
from .utils import suppress_cryptography_errors


def download_csr(modeladmin, request, queryset):
    if len(queryset) > 1:
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
    else:
        # At this point, we know there is only one item in the queryset
        # Django actions are only available when one or more items are selected
        # In other words, the queryset can't be empty
        csr = queryset[0].csr
        return FileResponse(
            BytesIO(csr.encode()),
            as_attachment=True,
            filename=f"{slugify(queryset[0].common_name)}_{queryset[0].pk}_csr.pem",
        )


@admin.register(SigningRequest)
class SigningRequestAdmin(admin.ModelAdmin):
    form = SigningRequestAdminForm
    list_display = (
        "common_name",
        "organization_name",
        "country_name",
        "state_or_province_name",
        "locality_name",
        "email_address",
    )
    list_filter = ("organization_name", "state_or_province_name", "locality_name")
    search_fields = ("common_name", "organization_name", "locality_name")
    fieldsets = (
        (
            _("Subject information"),
            {
                "fields": (
                    "common_name",
                    "organization_name",
                    "country_name",
                    "state_or_province_name",
                    "locality_name",
                    "email_address",
                ),
                "description": (
                    _(
                        "The CSR will be generated after entering"
                        " the information and submitting the data."
                    )
                ),
            },
        ),
        (
            _("Signing Request (CSR)"),
            {
                "fields": ("csr", "should_renew_csr"),
            },
        ),
        (
            _("Upload and verify certificate"),
            {
                "fields": ("certificate", "public_certificate"),
                "description": _(
                    "Upload the public certificate file here. "
                    "This will be used to verify the signature against the CSR "
                    "and create the certificate instance. The CSR needs to be saved"
                    " first (created) before uploading the certificate."
                ),
            },
        ),
    )
    list_display = (
        "common_name",
        "organization_name",
        "country_name",
        "state_or_province_name",
        "locality_name",
        "email_address",
    )
    list_filter = ("organization_name", "state_or_province_name", "locality_name")
    search_fields = ("common_name", "organization_name", "locality_name")
    readonly_fields = ("csr", "public_certificate")
    actions = [download_csr]

    def response_post_save_add(self, request, obj, post_url_continue=None):
        return HttpResponseRedirect(
            reverse("admin:simple_certmanager_signingrequest_change", args=(obj.pk,))
        )

    def response_post_save_change(self, request, obj):
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
