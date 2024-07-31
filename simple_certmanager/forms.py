from django import forms
from django.core.files import File
from django.utils.translation import gettext_lazy as _

from .csr_generation import generate_private_key_with_csr
from .models import Certificate, SigningRequest
from .utils import (
    BadPassword,
    KeyIsEncrypted,
    KeyIsNotEncrypted,
    decrypted_key_to_pem,
    load_pem_x509_private_key,
)
from .validators import PrivateKeyValidator


class SigningRequestAdminForm(forms.ModelForm):
    should_renew_csr = forms.BooleanField(
        label=_("Regenerate CSR"),
        help_text=_(
            "Check this box to regenerate the CSR from the above details. "
            "This will also generate a new private key."
        ),
        required=False,
    )

    class Meta:
        model = SigningRequest
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Show the "Regenerate CSR" checkbox, but only enable it for existing
        # instances.
        if not self.instance.pk:
            self.fields["should_renew_csr"].disabled = True

    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.cleaned_data.get("should_renew_csr", False):
            new_private_key, new_csr = generate_private_key_with_csr(
                common_name=self.cleaned_data["common_name"],
                country=self.cleaned_data["country_name"],
                state_or_province=self.cleaned_data["state_or_province_name"],
                locality=self.cleaned_data["locality_name"],
                organization_name=self.cleaned_data["organization_name"],
                email=self.cleaned_data["email_address"],
            )
            instance.private_key = new_private_key
            instance.csr = new_csr
        if commit:
            instance.save()
        return instance


def _read_and_reset(file_like: File):
    """
    Read a file field from the start of the file and set the pointer to the start.
    """
    file_like.seek(0)
    content = file_like.read()
    file_like.seek(0)
    return content


class CertificateAdminForm(forms.ModelForm):
    serial_number = forms.CharField(disabled=True, required=False)
    private_key_passphrase = forms.CharField(
        label=_("Passphrase"),
        help_text=_("Passphrase to decrypt the private key if it's encrypted."),
        required=False,
        widget=forms.PasswordInput,
    )

    class Meta:
        model = Certificate
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # ensure the private key validator runs *before* :meth:`clean`, since we want
        # to check that it looks like a private key first. The model-field validator
        # only runs *after* the form validation.
        self.fields["private_key"].validators.append(
            PrivateKeyValidator(allow_encrypted=True),
        )

        try:
            self.fields["serial_number"].initial = self.instance.serial_number
        except (FileNotFoundError, KeyError, ValueError):
            return

    def clean(self):
        super().clean()

        private_key: File | None = self.cleaned_data.get("private_key")
        # Normalize to ``None`` for empty-ish passphrases
        passphrase = self.cleaned_data.get("private_key_passphrase") or None

        if private_key:
            key_data = _read_and_reset(private_key)
            try:
                key = load_pem_x509_private_key(key_data, password=passphrase)
            except KeyIsEncrypted:
                self.add_error(
                    "private_key_passphrase",
                    _("Provide a passphrase to decrypt the private key."),
                )
            except KeyIsNotEncrypted:
                # instead of ignoring the password, report back as the user may have
                # accidentally uploaded the wrong key if they expected a password
                self.add_error(
                    "private_key_passphrase",
                    _(
                        "The private key is not encrypted, a passphrase is not "
                        "required."
                    ),
                )
            except BadPassword:
                self.add_error(
                    "private_key_passphrase",
                    _(
                        "Could not decrypt the private key with the provided "
                        "passphrase."
                    ),
                )
            else:
                is_encrypted = passphrase is not None
                if is_encrypted:
                    decrypted_key_data = decrypted_key_to_pem(key)
                    # replace the file contents to the decrypted key
                    private_key.truncate(0)
                    private_key.write(decrypted_key_data)
                    private_key.seek(0)
