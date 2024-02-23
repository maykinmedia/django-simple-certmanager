import logging
from functools import wraps
from os import PathLike
from typing import Any, Generator, Optional, Union

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from OpenSSL import crypto

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


def split_pem(pem: bytes) -> Generator[bytes, None, None]:
    "Split a concatenated pem into its constituent parts"
    mark = b"-----END CERTIFICATE-----"
    if mark not in pem:
        return
    end = pem.find(mark) + len(mark)
    yield pem[:end]
    yield from split_pem(pem[end:])


def load_pem_chain(pem: bytes) -> Generator[x509.Certificate, None, None]:
    for data in split_pem(pem):
        yield x509.load_pem_x509_certificate(data)


def check_pem(
    pem: bytes,
    ca: Union[bytes, str, PathLike] = certifi.where(),
    ca_path: Optional[Union[str, PathLike]] = None,
) -> bool:
    """Simple (possibly incomplete) sanity check on pem chain.

    If the pam passes this check it MAY be valid for use. This is only intended
    to catch blatant misconfigurations early. This gives NO guarantees on
    security nor authenticity.

    See all the context in the upstream issue:
    https://github.com/pyca/cryptography/issues/2381
    """
    # We need still need to use pyOpenSSL primitives for this:
    # https://github.com/pyca/cryptography/issues/6229
    # https://github.com/pyca/cryptography/issues/2381

    # Establish roots
    store = crypto.X509Store()
    store.load_locations(ca, ca_path)

    leaf, *chain = map(crypto.X509.from_cryptography, load_pem_chain(pem))

    # Create a context
    ctx = crypto.X509StoreContext(store, leaf, chain)
    try:
        ctx.verify_certificate()
    except crypto.X509StoreContextError:
        return False
    else:
        return True


def suppress_crypto_errors(func):
    """
    Decorator to suppress exceptions thrown while processing PKI data.
    """

    @wraps(func)
    def wrapper(*args, **kwargs) -> Optional[Any]:
        try:
            return func(*args, **kwargs)
        except (crypto.Error, ValueError) as exc:
            logger.warning(
                "Suppressed exception while attempting to process PKI data",
                exc_info=exc,
            )
            return None

    return wrapper
