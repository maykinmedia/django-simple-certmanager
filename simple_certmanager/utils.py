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
    except TypeError as exc:
        if (
            password is None
            and exc.args
            and (err := exc.args[0])
            and "Password was not given but private key is encrypted" in err
        ):
            raise KeyIsEncrypted("Private key is encrypted") from exc
        # an error we can't handle, so just re-raise and let it bubble up
        else:
            raise
    except ValueError as exc:
        if (
            password is not None
            and exc.args
            and (err := exc.args[0])
            and "Incorrect password?" in err
        ):
            raise BadPassword("Could not decrypt with the given password") from exc
        # an error we can't handle, so just re-raise and let it bubble up
        else:
            raise


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
