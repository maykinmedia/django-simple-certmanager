import sys

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.utils.translation import gettext_lazy as _

from ...models import Certificate
from ...mtls import VerificationError, check_mtls_connection


class Command(BaseCommand):
    """
    CLI tool to test correct client TLS certificate configuration.

    The full user experience is then along the lines of:

    1. Obtaining a client certificate (chain)

       * Generate a private key and CSR with the necessary information
       * Send the CSR to the CA and request them to sign a certificate
       * Receive the certificate and relevant intermediate certificates

    2. Upload the files and add the metadata to a Certificate instance (via the admin)

    3. Optionally, configure the root certificate of the server in a separate
       Certificate instance. Servers are required to send their intermediates in the
       chain according to the TLS spec.

    4. Test the mTLS connection using this management command.
    """

    help = "Check certificates for a mutual TLS connection"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "host",
            help=(
                "Host name to connect to, e.g. example.com. IP addresses will usually "
                "fail, so do not use them."
            ),
        )
        parser.add_argument(
            "--port",
            type=int,
            default=443,
            help="Port number, if not specified, 443 is used.",
        )
        parser.add_argument(
            "--client-cert",
            required=True,
            type=int,
            help=(
                "ID of the client certificate instance. The client "
                "certificate is required for the server to authenticate the client."
            ),
        )
        parser.add_argument(
            "--server-cert",
            required=False,
            type=int,
            help=(
                "ID of the server certificate instance. The server "
                "certificate is required if the server certificate chain is not signed "
                "by a public root (which is the case with self-signed certificates "
                "and/or private Certificate Authorities)."
            ),
        )

    def handle(self, *args, **options) -> None:
        host: str = options.pop("host")
        port: int = options.pop("port")
        client_cert_id: int = options.pop("client_cert")
        server_cert_id: int | None = options.pop("server_cert")

        certificates = Certificate.objects.in_bulk(
            [client_cert_id, server_cert_id], field_name="id"
        )
        if (client_cert := certificates.get(client_cert_id)) is None:
            raise CommandError(
                f"Client certificate with id {client_cert_id} does not exist."
            )

        if (server_cert := certificates.get(server_cert_id)) is None and server_cert_id:
            raise CommandError(
                f"Server certificate with id {server_cert_id} does not exist."
            )

        self.stdout.write(f"Connection test to: {host}:{port}")
        self.stdout.write(f"  * Using client certificate: {client_cert}")
        if server_cert:
            self.stdout.write(f"  * Using server CA: {server_cert}")

        self.stdout.write("\nRunning checks...")

        _first = True

        def check_callback(check: str):
            nonlocal _first
            if not _first:
                self.stdout.write("  OK")
            self.stdout.write(f"  -> {check}?", ending="")
            _first = False

        try:
            check_mtls_connection(
                host=host,
                port=port,
                client_cert=client_cert,
                server_ca=server_cert,
                check_callback=check_callback,
            )
        except VerificationError as exc:
            self.stdout.write("  FAIL")
            self.stderr.write(exc.args[0])
            sys.exit(1)
        else:
            self.stdout.write(" OK")
