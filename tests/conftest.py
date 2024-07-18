from pathlib import Path

import pytest
from cryptography import x509

from simple_certmanager.test.certificate_generation import cert_to_pem, gen_key, mkcert


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
