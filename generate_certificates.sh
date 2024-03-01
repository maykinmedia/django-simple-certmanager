#!/bin/bash
#
# Run script from the root of the repository.
#
# You need openssl on your system. See ./certificates/README.md for more
# information.
#

cd ./certificates

gen_root_ca() {
    # Generate private key
    openssl ecparam -out ca.key -name prime256v1 -genkey
    # Generate CSR
    openssl req -new -sha256 -key ca.key -out ca.csr \
        -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=Maykin/OU=Development/CN=CA"
    # And self-sign it
    openssl x509 -req -sha256 -days 365 -in ca.csr \
        -signkey ca.key -out ca.pem \
        -extfile ./ca-ext.ini
}

gen_server_cert() {
    # Generate private key
    openssl ecparam -out server.key -name prime256v1 -genkey
    # Generate CSR
    openssl req -new -sha256 -key server.key -out server.csr \
        -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=Maykin/OU=Development/CN=localhost"
    # Create cert signed by root
    openssl x509 -req -in server.csr \
        -CA ca.pem -CAkey ca.key -CAcreateserial \
        -out server.pem -days 365 -sha256 \
        -extfile <(printf "subjectAltName=DNS:localhost")
}

gen_client_cert() {
    # Generate private key
    openssl ecparam -out client.key -name prime256v1 -genkey
    # Generate CSR
    openssl req -new -sha256 -key client.key -out client.csr \
        -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=Maykin/OU=Development/CN=client"
    # Create cert signed by root
    openssl x509 -req -in client.csr \
        -CA ca.pem -CAkey ca.key -CAcreateserial \
        -out client.pem -days 365 -sha256
}

## Create the certificates

gen_root_ca
gen_server_cert
gen_client_cert
