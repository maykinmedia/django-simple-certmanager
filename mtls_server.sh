#!/bin/bash

openssl s_server \
    -cert ./certificates/server.pem \
    -key ./certificates/server.key \
    -port 8443 \
    -CAfile ./certificates/ca.pem \
    -verify_return_error \
    -Verify 1
