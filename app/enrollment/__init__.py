"""Endpoint enrollment and credential lifecycle interfaces."""

from .credentials import (
    CredentialStore,
    EndpointCredential,
    InMemoryCredentialStore,
    OSKeyringCredentialStore,
    ProtectedFileCredentialStore,
    SecretProtector,
    WindowsDPAPIProtector,
)
from .errors import (
    CredentialError,
    CredentialExpiredError,
    CredentialStorageError,
    EnrollmentError,
    MissingCredentialError,
)
from .service import (
    EnrollmentConfig,
    EnrollmentService,
    StoredCredentialAuthProvider,
)

__all__ = [
    "CredentialError",
    "CredentialExpiredError",
    "CredentialStorageError",
    "CredentialStore",
    "EndpointCredential",
    "EnrollmentConfig",
    "EnrollmentError",
    "EnrollmentService",
    "InMemoryCredentialStore",
    "MissingCredentialError",
    "OSKeyringCredentialStore",
    "ProtectedFileCredentialStore",
    "SecretProtector",
    "StoredCredentialAuthProvider",
    "WindowsDPAPIProtector",
]
