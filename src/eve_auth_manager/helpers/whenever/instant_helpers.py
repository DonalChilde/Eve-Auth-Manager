"""Helper functions for working with whenever.Instant."""

from whenever import Instant


def timestamp() -> int:
    """Return the current timestamp in seconds since the epoch."""
    return Instant.now().timestamp()


def timestamp_nanos() -> int:
    """Return the current timestamp in nanoseconds since the epoch."""
    return Instant.now().timestamp_nanos()


def from_now(timestamp: int) -> int:
    """Return the number of seconds from now until the given timestamp.

    Returns:
        The number of seconds from now until the given timestamp. If the timestamp is
            in the past, returns a negative number.
    """
    now = Instant.now().timestamp()
    return timestamp - now


def from_now_nanos(timestamp_nanos: int) -> int:
    """Return the number of nanoseconds from now until the given timestamp.

    Returns:
        The number of nanoseconds from now until the given timestamp. If the timestamp is
            in the past, returns a negative number.
    """
    now_nanos = Instant.now().timestamp_nanos()
    return timestamp_nanos - now_nanos
