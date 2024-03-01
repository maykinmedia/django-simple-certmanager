#!/bin/bash

openssl s_server \
    -cert ./docker/certificates/server.pem \
    -key ./docker/certificates/server.key \
    -WWW \
    -port 8443 \
    -CAfile ./docker/certificates/ca.pem \
    -verify_return_error \
    -Verify 1
