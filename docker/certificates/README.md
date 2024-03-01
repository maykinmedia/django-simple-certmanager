# README

This directory is mounted in the nginx container configured for mutual TLS.

Make sure to run the script `./generate_certificates.sh` from the root of the
repository to populate these certificates. They are deliberately excluded from
version control.

## Requirements

- `openssl` - OpenSSL must be present on your system to generate the certificates.

## Certificates/keys generated

**Root certificate authority**

- `ca.pem` - a self-signed root certificate, used to sign other certificates
- `ca.key` - private key belonging to certificate

**Server certificate**

- `server.pem`
- `server.key`

Private key and public certificate for the server, signed by `ca.pem`.

**Client certifiate**

- `client.pem`
- `client.key`

Private key and public certificate for the client, also signed by `ca.pem`.
