import logging
from functools import wraps
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key

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


def suppress_cryptography_errors(func):
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
