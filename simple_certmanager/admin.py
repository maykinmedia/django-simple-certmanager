from io import BytesIO
from zipfile import ZipFile

from django.contrib import admin, messages
from django.http import FileResponse, HttpRequest, HttpResponseRedirect
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
            BytesIO(csr.encode("ascii")),
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
    actions = [download_csr]
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
                "fields": ("csr",),
            },
        ),
        (
            _("Upload Signed Certificate"),
            {
                "fields": ("certificate", "public_certificate"),
            },
        ),
    )

    def get_object(
        self, request: HttpRequest, object_id: str, from_field: str | None = None
    ):
        """
        Here I only access the object so I can check which message to display
        to help the user. I don't need to change the object in any way.
        """
        object = super().get_object(request, object_id, from_field)
        if object and object.public_certificate:
            messages.warning(
                request,
                _(
                    "This request is signed therefore can not be edited."
                    " You can safely delete it."
                ),
            )

        return object

    def get_readonly_fields(
        self, request: HttpRequest, obj: SigningRequest | None = None
    ):
        "Make the CSR field read-only after it has been signed."
        readonly_fields = [
            "csr",
            "public_certificate",
        ]
        if obj and obj.public_certificate:
            readonly_fields.extend(
                [
                    "common_name",
                    "organization_name",
                    "country_name",
                    "state_or_province_name",
                    "locality_name",
                    "email_address",
                ]
            )
        return readonly_fields

    def response_post_save_add(self, request, obj, post_url_continue=None):
        "Redirects to the change form instead of the list view."
        return HttpResponseRedirect(
            reverse("admin:simple_certmanager_signingrequest_change", args=(obj.pk,))
        )

    def response_post_save_change(self, request, obj):
        "Redirects to the change form instead of the list view."
        return HttpResponseRedirect(
            reverse("admin:simple_certmanager_signingrequest_change", args=(obj.pk,))
        )

    def log_change(self, request, obj, message):
        "Logs that an object has been successfully changed."
        if obj.public_certificate:
            message = _("Signing Request processed and deleted.")
            super().log_deletion(request, obj, message)
        else:
            super().log_change(request, obj, message)


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
