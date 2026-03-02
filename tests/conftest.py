"""Shared pytest fixtures.

Factory functions live in tests/factories.py and can be imported directly.
This file provides pytest fixtures that need setup/teardown semantics.
"""

from __future__ import annotations

import pytest

from licensestoic.validator import LicenseCompatibilityValidator


@pytest.fixture()
def validator() -> LicenseCompatibilityValidator:
    """Provide a validator with flict availability pinned to False.

    This ensures tests use the builtin matrix regardless of whether flict
    is installed on the machine running the tests.
    """
    original = LicenseCompatibilityValidator._flict_available
    LicenseCompatibilityValidator._flict_available = None
    v = LicenseCompatibilityValidator()
    # After construction _flict_available is set; force builtin matrix
    LicenseCompatibilityValidator._flict_available = False
    yield v  # type: ignore[misc]
    LicenseCompatibilityValidator._flict_available = original
