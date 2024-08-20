from typing import NewType

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID

PrivateKey = NewType("PrivateKey", str)
CSR = NewType("CSR", str)


# 4096 as "sane default". 2048 is considered too small these days, and the Ansible
# plays generate keys with this key size too.
KEY_SIZE_BITS = 4096


def generate_private_key() -> PrivateKey:
    """
    Generate an RSA private key and return the PEM-encoded key data.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE_BITS,
        backend=default_backend(),
    )
    private_key_file_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # because it is PEM format, which is base64 encoding, we can safely decode the
    # bytes as ASCII
    return PrivateKey(private_key_file_bytes.decode("ascii"))


def generate_csr(
    key_pem: str,
    *,
    common_name: str,
    country: str = "",
    state_or_province: str = "",
    locality: str = "",
    organization_name: str = "",
    email: str = "",
) -> CSR:
    """
    Generate a CSR for the given private key and return the PEM-encoded CSR data.
    :arg key_pem: The private key to sign the CSR with, provided as PEM-encoded string.
    :arg common_name: The Subject common name, required.
    :arg country: The Subject country, as two-letter country code.
    :arg state_or_province: The Subject state or province name.
    :arg locality: The Subject locality (city) name.
    :arg organization_name: The Subject organization name.
    :arg email: The Subject email address.
    """
    assert common_name, "Common name may not be empty"
    # Load the private key to sign the CSR with.
    private_key = serialization.load_pem_private_key(
        key_pem.encode("ascii"),
        password=None,
        backend=default_backend(),
    )
    # type narrowing - we know we generate RSA private keys, see
    # :func:`generate_private_key`
    assert isinstance(private_key, rsa.RSAPrivateKey)
    # Only include the name attributes in the CSR that have non-empty values
    subject_name_attributes = [
        x509.NameAttribute(attr, value)
        for attr, value in [
            (NameOID.COMMON_NAME, common_name),
            (NameOID.ORGANIZATION_NAME, organization_name),
            (NameOID.LOCALITY_NAME, locality),
            (NameOID.STATE_OR_PROVINCE_NAME, state_or_province),
            (NameOID.COUNTRY_NAME, country),
            (NameOID.EMAIL_ADDRESS, email),
        ]
        if value
    ]
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(subject_name_attributes)
    )
    # Sign the CSR with our private key
    csr = csr_builder.sign(
        private_key, algorithm=hashes.SHA256(), backend=default_backend()
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return CSR(csr_pem)
