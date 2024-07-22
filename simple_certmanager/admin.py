from io import BytesIO
from zipfile import ZipFile

from django.contrib import admin
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from privates.admin import PrivateMediaMixin

from .forms import CertificateAdminForm, SigningRequestAdminForm
from .models import Certificate, SigningRequest
from .utils import suppress_cryptography_errors


def download_csr(modeladmin, request, queryset):
    if queryset.count() > 1:
        zip_file = BytesIO()
        with ZipFile(zip_file, "w") as zipf:
            for csr in queryset:
                csr_content = csr.csr
                csr_filename = f"{csr.common_name}_csr.pem"
                zipf.writestr(csr_filename, csr_content)
        zip_file.seek(0)
        response = HttpResponse(zip_file, content_type="application/zip")
        response["Content-Disposition"] = 'attachment; filename="csr.zip"'
        return response
    elif queryset.count() == 1:
        csr = queryset.first().csr
        response = HttpResponse(csr, content_type="application/x-pem-file")
        response["Content-Disposition"] = (
            f'attachment; filename="{queryset.first().common_name}_csr.pem"'
        )
        return response
    else:
        modeladmin.message_user(
            request,
            "No CSR selected.",
        )


@admin.register(SigningRequest)
class SigningRequestAdmin(PrivateMediaMixin, admin.ModelAdmin):
    model: type[SigningRequest]
    form = SigningRequestAdminForm
    fields = (
        "common_name",
        "organization_name",
        "country_name",
        "state_or_province_name",
        "email_address",
        "private_key",
        "csr",
        "certificate",
    )
    list_display = (
        "common_name",
        "organization_name",
        "country_name",
        "state_or_province_name",
        "email_address",
    )
    list_filter = ("organization_name", "state_or_province_name")
    readonly_fields = ("csr",)
    search_fields = ("common_name", "organization_name")
    private_media_fields = ("private_key",)
    private_media_no_download_fields = ("private_key",)
    actions = [download_csr]

    def response_add(self, request, obj, post_url_continue=None):
        return HttpResponseRedirect(
            reverse("admin:simple_certmanager_signingrequest_change", args=(obj.pk,))
        )

    def response_post_save_change(self, request, obj):
        if isinstance(obj, Certificate):
            return HttpResponseRedirect(
                reverse("admin:simple_certmanager_certificate_change", args=(obj.pk,))
            )
        return HttpResponseRedirect(
            reverse("admin:simple_certmanager_signingrequest_change", args=(obj.pk,))
        )

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        validated_certificate = form.cleaned_data.get("certificate")
        if validated_certificate:
            created_certificate = obj.create_certificate(validated_certificate)
            return self.response_post_save_change(request, created_certificate)


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
        "signing_request",
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
    readonly_fields = (
        "serial_number",
        "signing_request",
    )

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
