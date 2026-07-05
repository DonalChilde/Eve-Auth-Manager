"""Tests for whenever instant helper functions."""

import pytest

import eve_auth_manager.helpers.whenever.instant_helpers as instant_helpers


def test_timestamp_helpers_return_current_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timestamp helpers should forward values from whenever.Instant.now()."""

    class FakeInstantNow:
        def timestamp(self) -> int:
            return 123

        def timestamp_nanos(self) -> int:
            return 456_789

    class FakeInstant:
        @staticmethod
        def now() -> FakeInstantNow:
            return FakeInstantNow()

    monkeypatch.setattr(
        instant_helpers,
        "Instant",
        FakeInstant,
    )

    assert instant_helpers.timestamp() == 123
    assert instant_helpers.timestamp_nanos() == 456_789


def test_from_now_helpers_compute_signed_deltas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Relative-time helpers should subtract the current time from the target."""

    class FakeInstantNow:
        def timestamp(self) -> int:
            return 100

        def timestamp_nanos(self) -> int:
            return 1_000

    class FakeInstant:
        @staticmethod
        def now() -> FakeInstantNow:
            return FakeInstantNow()

    monkeypatch.setattr(
        instant_helpers,
        "Instant",
        FakeInstant,
    )

    assert instant_helpers.from_now(130) == 30
    assert instant_helpers.from_now(90) == -10
    assert instant_helpers.from_now_nanos(1_250) == 250
    assert instant_helpers.from_now_nanos(900) == -100
