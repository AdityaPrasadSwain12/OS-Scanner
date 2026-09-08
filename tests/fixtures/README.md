# Test-only TLS material

`tls_wronghost_cert.pem` and `tls_wronghost_key.pem` form a deliberately untrusted,
self-signed certificate pair for `wronghost.invalid`. Integration tests use it only to prove
that the scanner rejects untrusted chains and hostname mismatches.

The private key is public test data. It is not used by any deployed service, is not trusted by
the application, and must never be reused outside these tests.
