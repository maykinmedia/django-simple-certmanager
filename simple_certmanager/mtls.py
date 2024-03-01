"""
Mutual/client TLS testing utilities.
"""

import logging
import socket
import ssl
from types import ModuleType

from django.utils import timezone

from .constants import CertificateTypes
from .models import Certificate

certifi: ModuleType | None
try:
    import certifi
except ImportError:
    certifi = None

logger = logging.getLogger(__name__)


class VerificationError(Exception):
    pass


def check_mtls_connection(
    host: str,
    port: int,
    client_cert: Certificate,
    server_ca: Certificate | None = None,
    timeout: float = 3,
):
    """
    Initiate a (mutual) TLS connection attempt to the specified host and port.

    The configuration from the client certificate is used to authenticate the client,
    while the server CA configuration is used to verify the authenticity of the server.

    :arg host: string with hostname, suitable for the :mod:`socket` module. Note that
      IP addresses will typically fail because they're not present in the server
      certificate, instead only the DNS names are usually present.
    :arg port: integer port number to connect to, suitable for the :mod:`socket` module
    :arg client_cert: A certificate instance that holds the private key and public
      certificate to authenticate the client (this is us).
    :arg server_ca: An optional certificate instance of which the public certificate
      is used as certificate authority, meaning that any certificate signed by that
      public certificate is trusted. If not provided, either the :mod:`certifi` trust
      store is used if available, otherwise the system trust store is used (default
      Python :mod:`ssl` module behaviour).

    :raises: :class:`VerificationError` for any detected problems.
    """
    if client_cert.type != CertificateTypes.key_pair:
        raise VerificationError(
            "A client certificate must be of the private key + certificate pair type."
        )

    if not client_cert.is_valid_key_pair():
        raise VerificationError(
            "The client certificate private key and certificate do not match."
        )

    now = timezone.now()
    if client_cert.expiry_date < now:
        raise VerificationError("The client certificate is expired.")

    # check which CA bundle to use - it's a single file with concatenated certificates
    # in PEM format.
    default_bundle = certifi.where() if certifi is not None else None
    ca_bundle: str | None = (
        server_ca.public_certificate.path if server_ca else default_bundle
    )
    # when ca_bundle is None, create_default_context loads the default system root CA
    # certificates
    context = ssl.create_default_context(cafile=ca_bundle)

    # there is no way to check if the server actually requires a client certificate,
    # so instead we attempt a connection without and see if that raises the expected
    # error.
    address = (host, port)
    try:
        _attempt_connection(context, address, timeout=timeout)
    except ssl.SSLCertVerificationError as exc:
        using_ca = server_ca or "no"
        raise VerificationError(
            f"Could not verify the server certificate (using CA: {using_ca})"
        ) from exc
    except ssl.SSLError as exc:
        print(exc)
        requires_client_cert = True
    else:
        requires_client_cert = False

    if not requires_client_cert:
        raise VerificationError(
            "mTLS does not appear required. A connection without client chain/key "
            "was unexpectedly established."
        )

    # now configure the client certificate chain
    context.load_cert_chain(
        certfile=client_cert.public_certificate.path,
        keyfile=client_cert.private_key.path,
        password=_forbid_password,
    )
    _attempt_connection(context, address, timeout=timeout)


def _forbid_password():
    raise VerificationError("Password protected private keys are not supported.")


def _attempt_connection(
    context: ssl.SSLContext,
    address: tuple[str, int],
    timeout: float,
) -> None:
    """
    Create a TLS connection for the given context.

    Raises ssl errors if the context does not match the server requirements.
    """
    with socket.create_connection(address, timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=address[0]) as ssock:
            logger.debug("Connected using %s", ssock.version())
