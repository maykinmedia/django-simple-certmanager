import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import asymmetric, hashes, serialization


@pytest.fixture(scope="session")
def root_key() -> asymmetric.rsa.RSAPrivateKey:
    "RSA key for the RootCA"
    key = gen_key()
    # with (Path(__file__).parent / "data" / "test.key").open("rb") as f:
    #     return serialization.load_pem_private_key(f.read(), password=None)
    return key


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
def leaf_pem(root_cert: x509.Certificate, root_key) -> bytes:
    "A valid pem encoded certificate directly issued by the Root CA"
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
        subject_key=gen_key(),
        issuer=root_cert.subject,
        issuer_key=root_key,
        can_issue=False,
    )
    return to_pem(leaf_cert)


@pytest.fixture
def chain_pem(root_cert: x509.Certificate, root_key) -> bytes:
    "A valid pem encoded full certificate chain"
    inter_key = gen_key()
    intermediate_cert = mkcert(
        subject=x509.Name(
            [
                x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "NL"),
                x509.NameAttribute(
                    x509.oid.NameOID.ORGANIZATION_NAME, "Men in the Middle Ltd"
                ),
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "mitm.example.org"),
            ]
        ),
        subject_key=inter_key,
        issuer=root_cert.subject,
        issuer_key=root_key,
        can_issue=True,
    )
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
        subject_key=gen_key(),
        issuer=intermediate_cert.subject,
        issuer_key=inter_key,
        can_issue=False,
    )
    return b"".join(map(to_pem, [leaf_cert, intermediate_cert]))


@pytest.fixture
def broken_chain_pem(root_cert: x509.Certificate, root_key):
    """An invalid pem encoded full certificate chain.

    The intermediate is no a valid issuer.
    """
    inter_key = gen_key()
    intermediate_cert = mkcert(
        subject=x509.Name(
            [
                x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "NL"),
                x509.NameAttribute(
                    x509.oid.NameOID.ORGANIZATION_NAME, "Men in the Middle Ltd"
                ),
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "mitm.example.org"),
            ]
        ),
        subject_key=inter_key,
        issuer=root_cert.subject,
        issuer_key=root_key,
        can_issue=False,  # Middle isn't allowed to issue certs.
    )
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
        subject_key=gen_key(),
        issuer=intermediate_cert.subject,
        issuer_key=inter_key,
        can_issue=False,
    )
    return b"".join(map(to_pem, [leaf_cert, intermediate_cert]))


@pytest.fixture(scope="session")
def root_ca_path(root_cert, tmp_path_factory) -> Path:
    "A path to a temporary .pem for the Root CA"
    cert_path = tmp_path_factory.mktemp("fake_pki") / "fake_ca_cert.pem"
    with cert_path.open("wb") as f:
        f.write(to_pem(root_cert))
    return cert_path


def mkcert(subject, subject_key, issuer=None, issuer_key=None, can_issue=True):
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer if issuer else subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
    )

    if can_issue:
        cert = cert.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )

    cert = cert.sign(issuer_key if issuer_key else subject_key, hashes.SHA256())
    return cert


def to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def gen_key():
    return asymmetric.rsa.generate_private_key(public_exponent=0x10001, key_size=2048)
