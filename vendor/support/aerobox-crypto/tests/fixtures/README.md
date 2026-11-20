These certificates and private keys are public test fixtures for localhost.
They must never be used by a deployed server. Certificates contain only the
localhost DNS name and have a validity window starting in November 2026.
Tests use a fixed verification time in 2030.

OpenSSL generated the checked-in fixture files; OpenSSL is not a runtime,
build or test dependency. Tests load DER directly through the RustCrypto
provider, exercising ECDSA P-256 and RSA-2048 certificate authentication.
