"""
Helpers for x509 certificate generation.
"""

import datetime

from django.utils import timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
)


def mkcert(
    subject: x509.Name,
    subject_key: rsa.RSAPrivateKey,
    issuer: x509.Certificate | None = None,
    issuer_key: rsa.RSAPrivateKey | None = None,
    can_issue: bool = True,
):
    public_key = subject_key.public_key()
    issuer_name = issuer.subject if issuer else subject
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(timezone.now())
        .not_valid_after(timezone.now() + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        # required for certificate chain validation, even in leaf certificates
        .add_extension(
            x509.BasicConstraints(ca=can_issue, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=can_issue,
                crl_sign=can_issue,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
    )

    if issuer:
        ski_ext = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        cert = cert.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ski_ext.value
            ),
            critical=False,
        )

    return cert.sign(issuer_key if issuer_key else subject_key, hashes.SHA256())


def key_to_pem(key: PrivateKeyTypes, passphrase: str = "") -> bytes:
    """
    Serialize a private key to PEM, optionally encrypting it.
    """
    # UNSURE if utf-8 is the encoding that is also used by openssl and friends
    _passphrase = passphrase.encode("utf-8") if passphrase else None
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=(
            BestAvailableEncryption(_passphrase) if _passphrase else NoEncryption()
        ),
    )


def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def gen_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=0x10001, key_size=2048)
