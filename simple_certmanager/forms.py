from typing import Any

from django import forms
from django.core.files import File
from django.utils.translation import gettext_lazy as _

from cryptography import x509

from .models import Certificate, SigningRequest
from .utils import (
    BadPassword,
    KeyIsEncrypted,
    KeyIsNotEncrypted,
    decrypted_key_to_pem,
    load_pem_x509_private_key,
)
from .validators import PrivateKeyValidator, PublicCertValidator


class SigningRequestAdminForm(forms.ModelForm):
    certificate = forms.FileField(
        required=False,
        help_text=_(
            "Upload the public certificate file here. "
            "This will be used to verify the signature against the CSR "
            "and create the certificate instance."
        ),
        label=_("Upload Signed Certificate"),
        validators=[PublicCertValidator()],
    )

    class Meta:
        model = SigningRequest
        fields = "__all__"

    def save(self, commit: bool = True) -> Any:
        # Save the subject
        instance = super().save(commit)
        # Handle the certificate file upload
        validated_certificate = self.cleaned_data.get("certificate")
        if validated_certificate:
            instance.create_certificate(validated_certificate)
        if commit:
            instance.save()
        return instance

    def clean_certificate(self) -> File | None:
        file = self.cleaned_data["certificate"]
        if file is None:
            return file

        if self.instance.public_certificate:
            raise forms.ValidationError(
                _(
                    "A certificate already exists for this CSR. "
                    "Delete the certificate first.",
                ),
            )

        certificate_data = _read_and_reset(file)

        # Load the certificate and private key
        # Private key is generated so won't throw an error
        # Public certificate is validated so won't throw an error
        certificate = x509.load_pem_x509_certificate(certificate_data)
        private_key = load_pem_x509_private_key(
            self.instance.private_key.encode("ascii")
        )

        # Check if the certificate matches the CSR by comparing the public keys
        private_key_pubkey = private_key.public_key()
        certificate_public_key = certificate.public_key()
        match = private_key_pubkey == certificate_public_key
        if not match:
            raise forms.ValidationError(
                _("Certificate does not match the signature from the actual CSR."),
            )

        return file


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
