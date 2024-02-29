import logging
from functools import wraps
from typing import Any, Optional, Union

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


def _decode(value: Union[str, bytes]) -> str:
    # attr.value can be bytes, in which case it is must be an UTF8String or
    # PrintableString (the latter being a subset of ASCII, thus also a subset of UTF8)
    # See https://www.rfc-editor.org/rfc/rfc5280.txt
    if not isinstance(value, bytes):
        return value
    return value.decode("utf8")


def pretty_print_certificate_components(x509name: x509.Name) -> str:
    bits = (
        f"{attr.rfc4514_attribute_name}: {_decode(attr.value)}" for attr in x509name
    )
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
