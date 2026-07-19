"""Utilities for generating RFC 7636 PKCE verifier and S256 challenge values."""

import base64
import hashlib
import secrets
import string
from dataclasses import dataclass


@dataclass(slots=True)
class PKCEData:
    """PKCE values required across the OAuth authorization flow.

    Attributes:
        code_challenge: Base64url-encoded SHA-256 digest of the verifier,
            without padding, for the authorization request.
        code_verifier: High-entropy RFC 7636 verifier to retain and send to
            the token endpoint.
    """

    code_challenge: str
    code_verifier: str


def generate_code_challenge_and_verifier() -> PKCEData:
    """Generate PKCE verifier and S256 challenge values.

    Creates a 64-character verifier using RFC 7636 unreserved characters, then
    derives the corresponding S256 code challenge by hashing the verifier with
    SHA-256 and encoding the digest with unpadded base64url.

    Returns:
        PKCEData containing the verifier and its derived code challenge.

    Raises:
        ValueError: If the generated verifier violates RFC 7636 length or
            character constraints. This indicates an internal invariant failure.
    """
    allowed_chars = string.ascii_letters + string.digits + "-._~"

    # RFC 7636 requires code_verifier length to be between 43 and 128 chars.
    code_verifier = "".join(secrets.choice(allowed_chars) for _ in range(64))

    if not (43 <= len(code_verifier) <= 128):
        raise ValueError("PKCE code_verifier length must be between 43 and 128")

    if not all(ch in allowed_chars for ch in code_verifier):
        raise ValueError("PKCE code_verifier contains invalid characters")

    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    return PKCEData(code_challenge=code_challenge, code_verifier=code_verifier)
