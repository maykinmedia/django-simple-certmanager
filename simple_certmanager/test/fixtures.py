import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from .certificate_generation import cert_to_pem, gen_key, key_to_pem, mkcert


@pytest.fixture(scope="session")
def root_key() -> rsa.RSAPrivateKey:
    "RSA key for the RootCA"
    return gen_key()


@pytest.fixture(scope="session")
def root_cert(root_key) -> x509.Certificate:
    "Certificate for the RootCA"
    return mkcert(
        x509.Name(
            [
                x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "NL"),
                x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "NH"),
                x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, "Amsterdam"),
                x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Root CA"),
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "rootca.example.org"),
            ]
        ),
        root_key,
    )


@pytest.fixture
def leaf_keypair(
    root_cert: x509.Certificate, root_key
) -> tuple[rsa.RSAPrivateKey, bytes]:
    """
    A private key and valid pem encoded certificate directly issued by the Root CA
    """
    privkey = gen_key()
    leaf_cert = mkcert(
        subject=x509.Name(
            [
                x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "NL"),
                x509.NameAttribute(
                    x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "Some-State"
                ),
                x509.NameAttribute(
                    x509.oid.NameOID.ORGANIZATION_NAME, "Internet Widgits Pty Ltd"
                ),
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "widgits.example.org"),
            ]
        ),
        subject_key=privkey,
        issuer=root_cert,
        issuer_key=root_key,
        can_issue=False,
    )
    return privkey, cert_to_pem(leaf_cert)


@pytest.fixture
def encrypted_keypair(
    leaf_keypair: tuple[rsa.RSAPrivateKey, bytes]
) -> tuple[bytes, bytes]:
    """
    A private key + certificate pair where the private key is encrypted.
    """
    key, cert_pem = leaf_keypair
    encrypted_private_key_pem = key_to_pem(key, passphrase="SUPERSECRET🔐")
    return encrypted_private_key_pem, cert_pem
