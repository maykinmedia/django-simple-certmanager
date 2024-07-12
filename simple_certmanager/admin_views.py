from django import forms
from django.core.files.base import ContentFile
from django.views import generic

from OpenSSL import crypto

from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate, CertificateSigningRequestInfo


class CertificateSigningRequestInfoForm(forms.ModelForm):
    class Meta:
        model = CertificateSigningRequestInfo
        fields = [
            "country_name",
            "organization_name",
            "state_or_province_name",
            "email_address",
            "common_name",
        ]
        widgets = {
            "country_name": forms.TextInput(attrs={"class": "form-control"}),
            "organization_name": forms.TextInput(attrs={"class": "form-control"}),
            "state_or_province_name": forms.TextInput(attrs={"class": "form-control"}),
            "email_address": forms.EmailInput(attrs={"class": "form-control"}),
            "common_name": forms.TextInput(attrs={"class": "form-control"}),
        }


class GenerateCertificateView(generic.edit.CreateView):
    template_name_suffix = "_form"
    model = CertificateSigningRequestInfo
    form_class = CertificateSigningRequestInfoForm
    success_url = "/admin/simple_certmanager/certificate/"

    def form_valid(self, form):
        results = {
            "country": form.cleaned_data["country_name"],
            "organization": form.cleaned_data["organization_name"],
            "state": form.cleaned_data["state_or_province_name"],
            "email_address": form.cleaned_data["email_address"],
            "common_name": form.cleaned_data["common_name"],
        }

        if not results["common_name"].startswith("saml."):
            results["common_name"] = "saml." + results["common_name"]

        try:
            private_key, csr = self.create_csr(
                common_name=results["common_name"],
                country=results["country"],
                state=results["state"],
                organization=results["organization"],
                email_address=results["email_address"],
            )

            self.save_certificate(results, private_key, csr)
        except Exception as e:
            form.add_error(None, str(e))
            return self.form_invalid(form)

        return super().form_valid(form)

    def save_certificate(self, results, private_key, csr):
        private_key_file = ContentFile(private_key, name="private_key.pem")
        csr_file = ContentFile(csr, name="csr.pem")

        # Save the private key and CSR to the right location
        info = CertificateSigningRequestInfo.objects.create(
            country_name=results["country"],
            organization_name=results["organization"],
            state_or_province_name=results["state"],
            email_address=results["email_address"],
            common_name=results["common_name"],
        )
        db_certificate = Certificate.objects.create(
            type=CertificateTypes.cert_only,
            private_key=private_key_file,
            csr=csr_file,
            info=info,
        )
        db_certificate.label = (
            f"#{db_certificate.id} - {results['organization']} certificate"
        )
        db_certificate.save()

    def get_context_data(self, **kwargs):
        return super().get_context_data(**kwargs)

    def create_csr(
        self,
        common_name,
        country=None,
        state=None,
        city=None,
        organization=None,
        organizational_unit=None,
        email_address=None,
    ):
        """
        Args:
            common_name (str).

            country (str).

            state (str).

            city (str).

            organization (str).

            organizational_unit (str).

            email_address (str).

        Returns:
            (str, str).  Tuple containing private key and certificate
            signing request (PEM).
        """
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        req = crypto.X509Req()
        req.get_subject().CN = common_name
        if country:
            req.get_subject().C = country
        if state:
            req.get_subject().ST = state
        if city:
            req.get_subject().L = city
        if organization:
            req.get_subject().O = organization  # noqa
        if organizational_unit:
            req.get_subject().OU = organizational_unit
        if email_address:
            req.get_subject().emailAddress = email_address

        req.set_pubkey(key)
        req.sign(key, "sha256")

        private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

        csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

        return private_key, csr
