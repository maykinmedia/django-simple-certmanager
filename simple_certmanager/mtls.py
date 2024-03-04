"""
Mutual/client TLS testing utilities.
"""

import logging
import socket
import ssl
from dataclasses import dataclass
from types import ModuleType
from typing import Callable, Literal, TypeAlias

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


class UnexpectedSuccessfulConnectionError(VerificationError):
    pass


class RequirementMissingError(Exception):
    pass


def noop(check: str):
    pass


@dataclass
class BaseCheck:
    """
    Check a certificate/key pair for validity.

    Hostname and port number are combined to make up the address to connect to. The
    connection itself depends on the particular check type used.

    Subclasses should use the provided information to make real mTLS connections and
    verify that everything is as expected.
    """

    host: str
    """
    Hostname string to connect with, without protocol.

    Note that IP addresses will typically fail because they're not present in the server
    certificate, instead only the DNS names are usually present.
    """
    port: int
    """
    Integer port number to connect to.
    """
    client_cert: Certificate
    """
    A certificate instance that holds the private key and public certificate to
    authenticate the client (this is us).
    """
    server_ca: Certificate | None = None
    """
    An optional certificate instance of which the public certificate
    is used as certificate authority, meaning that any certificate signed by that
    public certificate is trusted. If not provided, the check-specific trust store is
    used (:mod:`certifi` for HTTP if available, system trust store otherwise).

    See the Python :mod:`ssl` module behaviour for a reference.
    """
    timeout: float = 3
    """
    Connect/read/write timeout value.

    If the remote end hangs, this will abort the connection.
    """
    check_callback: Callable[[str], None] = noop
    """
    Callback to invoke when performing a check step.

    The callable will be called with a string summary of the check being performed.
    """
    strict: bool = True
    """
    In strict mode, additional checks are performed that may not be performed during
    runtime by the remote host.
    """

    def __post_init__(self):
        self.check_requirements()

    def __call__(self) -> None:
        """
        Perform the actual connection checks.
        """
        self._validate_certificate()
        self.perform_check()

    def check_requirements(self) -> None:
        """
        Feature detection hook for subclasses.

        :raises RequirementMissingError: if prerequisites are not met.
        """
        pass

    def perform_check(self) -> None:
        """
        Hook to perform the protocol-specific check(s).
        """
        pass

    def _validate_certificate(self) -> None:
        """
        Check certificate instances for correct configuration.

        This check only performs sanity checks on the provided arguments without making
        real TCP connections.
        """
        self.check_callback("client certificate type")
        if self.client_cert.type != CertificateTypes.key_pair:
            raise VerificationError(
                "A client certificate must be of the private key + certificate pair "
                "type."
            )

        self.check_callback("valid client key pair")
        if not self.client_cert.is_valid_key_pair():
            raise VerificationError(
                "The client certificate private key and certificate do not match."
            )

        if self.strict:
            now = timezone.now()
            self.check_callback("client certificate expired")
            if self.client_cert.expiry_date < now:
                raise VerificationError("The client certificate is expired.")


class SocketCheck(BaseCheck):
    """
    Check the mTLS connection at the raw socket level.

    Opens a socket in mTLS mode and attempts to write/read data. Servers may reject
    the connection at the socket level already, which is the simplest check to perform.

    However, when servers perform the client verification *after* establishing a
    connection, this check may incorrectly report correct configuration. To avoid this,
    we recommend keeping strict mode enabled.
    """

    def perform_check(self) -> None:
        """
        Initiate a (mutual) TLS connection attempt to the specified host and port.

        The configuration from the client certificate is used to authenticate the
        client, while the server CA configuration is used to verify the authenticity of
        the server.

        In strict mode, a connection is attempted without providing the client
        certificate, which is expected to raise an exception. If this doesn't happen,
        it's an indicator that the service may not require a client certificate at all.
        """
        # check which CA bundle to use - it's a single file with concatenated
        # certificates in PEM format.
        default_bundle = certifi.where() if certifi is not None else None
        ca_bundle: str | None = (
            self.server_ca.public_certificate.path if self.server_ca else default_bundle
        )
        # when ca_bundle is None, create_default_context loads the default system root
        # CA certificates
        context = ssl.create_default_context(cafile=ca_bundle)

        if self.strict:
            self.check_callback("mTLS required")
            try:
                self._wrapped_connection_attempt(context)
            except ssl.SSLError as exc:
                logger.debug(
                    "Got expected SSL error when attempting connection without "
                    "client cert",
                    exc_info=exc,
                )
            else:
                raise UnexpectedSuccessfulConnectionError(
                    "mTLS does not appear required. A connection without client "
                    "chain/key was unexpectedly established. You may need to use a "
                    "different check type (like HTTPSCheck)."
                )

        def _forbid_password():
            raise VerificationError(
                "Password protected private keys are not supported."
            )

        # configure the client certificate chain and make a connection attempt
        context.load_cert_chain(
            certfile=self.client_cert.public_certificate.path,
            keyfile=self.client_cert.private_key.path,
            password=_forbid_password,
        )
        self.check_callback("client certificate accepted")
        try:
            self._wrapped_connection_attempt(context)
        except ssl.SSLError as exc:
            raise VerificationError("Client key/certificate appear invalid.") from exc

    def _wrapped_connection_attempt(self, context: ssl.SSLContext):
        try:
            self._attempt_connection(context)
        except ConnectionRefusedError as exc:
            raise VerificationError(
                f"Could not establish a connection to {self.host}:{self.port}"
            ) from exc
        except ssl.SSLCertVerificationError as exc:
            using_ca = self.server_ca or "no"
            raise VerificationError(
                f"Could not verify the server certificate (using CA: {using_ca})"
            ) from exc

    def _attempt_connection(self, context: ssl.SSLContext):
        """
        Create a TLS connection for the given context.

        Raises ssl errors if the context does not match the server requirements.
        """
        address = (self.host, self.port)
        with socket.create_connection(address, timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=address[0]) as ssock:
                logger.debug("Connected using %s", ssock.version())
                logger.debug(
                    "Sending and receiving some data to force the handshake"
                    "to finish."
                )
                try:
                    ssock.send(b"-mTLS verification-")
                    ssock.recv()
                # timeouts are okay, we're sending BS data anyway. We are looking
                # for ssl errors instead.
                except TimeoutError:
                    pass


HttpMethods: TypeAlias = Literal["GET", "POST", "HEAD"]


@dataclass
class HTTPCheck(BaseCheck):
    method: HttpMethods = "GET"
    path: str = "/"

    def check_requirements(self) -> None:
        try:
            import requests  # noqa
        except ImportError:
            raise RequirementMissingError(
                "The %r check requires the 'requests' library to be installed."
                % type(self)
            )

    def perform_check(self) -> None:
        """
        Make a real HTTP request and fail on HTTP 4xx and 5xx errors.
        """
        # Make a call without the client certificate, ensuring mTLS is actually
        # required.
        if self.strict:
            response = self._make_request()
            if not 400 <= (code := response.status_code) < 600:
                raise UnexpectedSuccessfulConnectionError(
                    "mTLS does not appear required. A connection without client "
                    f"chain/key returned an HTTPresponse with status code {code}."
                )

        # Make HTTP call with client certificate
        cert = (
            self.client_cert.public_certificate.path,
            self.client_cert.private_key.path,
        )
        response = self._make_request(cert=cert)
        if 400 <= (code := response.status_code) < 600:
            raise VerificationError(
                f"mTLS request failed, got HTTP response code {code}."
            )

    def _make_request(self, cert: tuple[str, str] | None = None):
        import requests

        address = f"{self.host}:{self.port}"
        url = f"https://{address}{self.path}"

        # check if we need to use a custom CA bundle to verify the server certificate
        verify: str | bool = (
            self.server_ca.public_certificate.path if self.server_ca else True
        )
        try:
            return requests.request(
                method=self.method,
                url=url,
                verify=verify,
                timeout=self.timeout,
                cert=cert,
            )
        except requests.ConnectionError as exc:
            raise VerificationError(f"Could not connect to {address}.") from exc
        except requests.RequestException as exc:
            raise VerificationError("Got request error %s" % exc) from exc
