import logging
from functools import wraps
from pathlib import Path
from typing import Any, Optional

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

logger = logging.getLogger(__name__)


def load_pem_x509_private_key(data: bytes):
    """
    Small wrapper around the ``cryptography.hazmat`` private key loader.

    Nothing in this code is really specific to x509, but the function name expresses
    our *intent* to only deal with x509 certificate/key pairs.
    """
    # passwords are not supported
    return load_pem_private_key(data, password=None)


def pretty_print_certificate_components(x509name: x509.Name) -> str:
    bits = (f"{attr.rfc4514_attribute_name}: {attr.value}" for attr in x509name)
    return ", ".join(bits)


def check_pem(pem: bytes, ca: str | Path = certifi.where()) -> bool:
    """Simple (possibly incomplete) sanity check on pem chain.

    If the pam passes this check it MAY be valid for use. This is only intended
    to catch blatant misconfigurations early. This gives NO guarantees on
    security nor authenticity.

    Relevant documentation: https://cryptography.io/en/stable/x509/verification/

    See all the context in the upstream issue:
    https://github.com/pyca/cryptography/issues/2381

    :arg pem: a certificate or chain of certificates in PEM format.
    :arg ca: path to the root Certificate Authority bundle.

    .. todo: The default for ``ca`` should probably support a setting so that
       self_certifi paths/dirs can be taken into account, or maybe consider the envvar
       ``REQUESTS_CA_BUNDLE``. This will make it possible to support the G1 Private root.
    """
    # normalize to Path
    if isinstance(ca, str):
        ca = Path(ca)

    [leaf, *intermediates] = x509.load_pem_x509_certificates(pem)
    root_certificates = x509.load_pem_x509_certificates(ca.read_bytes())

    store = Store(root_certificates)
    builder = PolicyBuilder().store(store)

    # extract the DNS name from the leaf certificate - we don't really care about the
    # exact host name for the chain validation since we don't know which hosts will be
    # connected to with this certificate - that only happens at runtime. So, we use the
    # first entry.
    # XXX: this can crash if the SAN extension is not present or no DNS names are
    # specified - it's unclear if those are situations we need to support or not.
    # Probably the validation of the (leaf) certificate itself should enforce the
    # presence of this information.
    san_extension = leaf.extensions.get_extension_for_oid(
        x509.OID_SUBJECT_ALTERNATIVE_NAME
    ).value
    assert isinstance(san_extension, x509.SubjectAlternativeName)
    dns_names = san_extension.get_values_for_type(x509.DNSName)
    dns_name = x509.DNSName(dns_names[0])
    verifier = builder.build_server_verifier(dns_name)

    try:
        verifier.verify(leaf, intermediates)
        return True
    except VerificationError:
        return False


def suppress_crypto_errors(func):
    """
    Decorator to suppress exceptions thrown while processing PKI data.
    """

    @wraps(func)
    def wrapper(*args, **kwargs) -> Optional[Any]:
        try:
            return func(*args, **kwargs)
        except ValueError as exc:
            logger.warning(
                "Suppressed exception while attempting to process PKI data",
                exc_info=exc,
            )
            return None

    return wrapper
