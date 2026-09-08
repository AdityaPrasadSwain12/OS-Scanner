"""Enrollment and local credential failure categories."""


class EnrollmentError(RuntimeError):
    pass


class CredentialError(EnrollmentError):
    pass


class MissingCredentialError(CredentialError):
    pass


class CredentialExpiredError(CredentialError):
    pass


class CredentialStorageError(CredentialError):
    pass
