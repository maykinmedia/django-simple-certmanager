# Test files for mTLS via simple_certmanager.Certificate models

## Certificate and key

The test.certificate and the test.key were generated using the following command:

```bash
openssl req -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out test.certificate -keyout test.key
```

These tests will potentially start failing once the test certificate expires.
