import logging
from functools import wraps
from typing import Callable, ParamSpec, TypeVar

from django.utils.encoding import force_str

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

logger = logging.getLogger(__name__)


class PrivateKeyError(Exception):
    pass


class KeyIsEncrypted(PrivateKeyError):
    pass


class KeyIsNotEncrypted(PrivateKeyError):
    pass


class BadPassword(PrivateKeyError):
    pass


def load_pem_x509_private_key(data: bytes, password: str | None = None):
    """
    Small wrapper around the ``cryptography.hazmat`` private key loader.

    Nothing in this code is really specific to x509, but the function name expresses
    our *intent* to only deal with x509 certificate/key pairs.
    """
    _password = password.encode("utf-8") if password is not None else None
    try:
        return load_pem_private_key(data, password=_password)

    # The exception type determines the kind of problem, relying on the exception
    # messages themselves is too fragile. See documentation:
    # https://cryptography.io/en/42.0.8/hazmat/primitives/asymmetric/
    # serialization/#cryptography.hazmat.primitives.serialization.load_pem_private_key
    except TypeError as exc:
        if _password is None:
            raise KeyIsEncrypted("No password for encrypted key given") from exc
        else:
            raise KeyIsNotEncrypted("Password given but key is not encrypted") from exc
    except ValueError as exc:
        if _password is None:
            raise
        # could be wrong password, could also be the right password but something went
        # wrong in the encrypted data...
        raise BadPassword("Could not decrypt with the given password") from exc


def decrypted_key_to_pem(key: PrivateKeyTypes):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def pretty_print_certificate_components(x509name: x509.Name) -> str:
    # attr.value can be bytes, in which case it is must be an UTF8String or
    # PrintableString (the latter being a subset of ASCII, thus also a subset of UTF8)
    # See https://www.rfc-editor.org/rfc/rfc5280.txt
    bits = (
        f"{attr.rfc4514_attribute_name}: {force_str(attr.value, encoding='utf-8')}"
        for attr in x509name
    )
    return ", ".join(bits)


T = TypeVar("T")
P = ParamSpec("P")


def suppress_cryptography_errors(func: Callable[P, T], /) -> Callable[P, T | None]:
    """
    Decorator to suppress exceptions thrown while processing PKI data.
    """

    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T | None:
        try:
            return func(*args, **kwargs)
        except ValueError as exc:
            logger.warning(
                "Suppressed exception while attempting to process PKI data",
                exc_info=exc,
            )
            return None

    return wrapper
