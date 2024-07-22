import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import asymmetric, hashes, serialization

from simple_certmanager.models import SigningRequest
from simple_certmanager.test.certificate_generation import cert_to_pem, gen_key

pytest_plugins = ["simple_certmanager.test.fixtures"]


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
        issuer=root_cert,
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
        issuer=intermediate_cert,
        issuer_key=inter_key,
        can_issue=False,
    )
    return b"".join(map(cert_to_pem, [leaf_cert, intermediate_cert]))


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
        issuer=root_cert,
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
        issuer=intermediate_cert,
        issuer_key=inter_key,
        can_issue=False,
    )
    return b"".join(map(cert_to_pem, [leaf_cert, intermediate_cert]))


@pytest.fixture(scope="session")
def root_ca_path(root_cert, tmp_path_factory) -> Path:
    "A path to a temporary .pem for the Root CA"
    cert_path = tmp_path_factory.mktemp("fake_pki") / "fake_ca_cert.pem"
    with cert_path.open("wb") as f:
        f.write(cert_to_pem(root_cert))
    return cert_path


@pytest.fixture
def temp_private_root(tmp_path, settings):
    tmpdir = tmp_path / "private-media"
    tmpdir.mkdir()
    location = str(tmpdir)
    settings.PRIVATE_MEDIA_ROOT = location
    settings.SENDFILE_ROOT = location
    return settings


def mkcert(subject, subject_key, issuer=None, issuer_key=None, can_issue=True):
    public_key = subject_key.public_key()
    issuer_name = issuer.subject if issuer else subject
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
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

    cert = cert.sign(issuer_key if issuer_key else subject_key, hashes.SHA256())
    return cert


def to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def signing_request_factory():
    def create_signing_request(**kwargs):
        return SigningRequest.objects.create(**kwargs)

    return create_signing_request
