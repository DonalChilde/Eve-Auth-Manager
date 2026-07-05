"""Helpers for generating cryptographically secure random alphanumeric strings."""

import secrets
import string


def generate_secure_random_string(length: int) -> str:
    """Generate a cryptographically secure alphanumeric string.

    Uses uppercase letters, lowercase letters, and digits, making it suitable
    for OAuth state values and other non-human-facing random identifiers.

    Args:
        length: Number of characters to generate.

    Returns:
        A securely generated random string of the requested length.

    Raises:
        ValueError: If length is less than 1.
    """
    if length < 1:
        raise ValueError("length must be greater than 0")

    # Define the possible characters (can also add punctuation if needed)
    characters = string.ascii_letters + string.digits

    # Generate the secure random string using secrets.choice
    secure_random_string = "".join(secrets.choice(characters) for _ in range(length))

    return secure_random_string
