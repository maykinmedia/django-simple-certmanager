from os import PathLike
from typing import Generator, Optional, Union

import certifi
from cryptography import x509
from OpenSSL import crypto


def pretty_print_certificate_components(x509name) -> str:
    components = [
        (label.decode("utf-8"), value.decode("utf-8"))
        for (label, value) in x509name.get_components()
    ]
    return ", ".join([f"{label}: {value}" for (label, value) in components])


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
