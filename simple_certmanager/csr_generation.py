from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID

# These methods make use of the SigningRequest model to generate a private key and CSR
# It is not imported here to avoid circular imports


def generate_csr_and_private_key(signing_request):
    generate_private_key(signing_request)

    if not signing_request.csr:
        # Generate CSR if not present
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = generate_csr(signing_request, csr_builder)

        # Load private key for signing CSR
        private_key = serialization.load_pem_private_key(
            signing_request.private_key.encode(),
            password=None,
            backend=default_backend(),
        )

        # Sign CSR with private key
        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())
        # Only store the CSR bytes in the text field
        signing_request.csr = csr.public_bytes(serialization.Encoding.PEM).decode()


def generate_csr(signing_request, csr_builder):
    csr_builder = csr_builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, signing_request.country_name),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME,
                    signing_request.state_or_province_name,
                ),
                x509.NameAttribute(
                    NameOID.LOCALITY_NAME, signing_request.organization_name
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, signing_request.organization_name
                ),
                x509.NameAttribute(NameOID.COMMON_NAME, signing_request.common_name),
                x509.NameAttribute(
                    NameOID.EMAIL_ADDRESS, signing_request.email_address
                ),
            ]
        )
    )

    return csr_builder


def generate_private_key(signing_request):
    if not signing_request.private_key:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        private_key_file_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Only store the private key bytes in the text field
        signing_request.private_key = private_key_file_bytes.decode()
