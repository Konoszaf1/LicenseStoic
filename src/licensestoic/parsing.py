"""License expression parsing adapter wrapping the license-expression library.

Layer 1 component: converts raw license strings into structured LicenseExpression
objects with validated SPDX identifiers.
"""

from __future__ import annotations

from typing import Any

from license_expression import (
    ExpressionError,
    LicenseSymbol,
    LicenseWithExceptionSymbol,
    get_spdx_licensing,
)

from licensestoic.models import LicenseExpression

# Module-level singleton — the SPDX licensing object is expensive to create
# but stateless once built.
_spdx_licensing = get_spdx_licensing()


def parse_license_expression(raw: str) -> LicenseExpression:
    """Parse a raw license string into a structured LicenseExpression.

    Attempts SPDX parsing first.  Falls back to marking as invalid SPDX if
    parsing fails, preserving the raw text for downstream LLM classification.
    """
    try:
        parsed = _spdx_licensing.parse(raw, validate=True)
    except ExpressionError:
        return LicenseExpression(
            spdx_expression=raw,
            identifiers=[],
            is_valid_spdx=False,
            raw_text=raw,
        )

    # parse() returns None for empty/whitespace-only strings
    if parsed is None:
        return LicenseExpression(
            spdx_expression=raw,
            identifiers=[],
            is_valid_spdx=False,
            raw_text=raw,
        )

    identifiers = _extract_identifiers(parsed)
    deprecated = _has_deprecated(parsed)

    return LicenseExpression(
        spdx_expression=str(parsed),
        identifiers=identifiers,
        is_valid_spdx=True,
        is_deprecated=deprecated,
        raw_text=raw,
    )


def validate_spdx(raw: str) -> list[str]:
    """Return a list of validation error messages (empty = valid)."""
    try:
        _spdx_licensing.parse(raw, validate=True)
        return []
    except ExpressionError as exc:
        return [str(exc)]


def _extract_identifiers(parsed: Any) -> list[str]:
    """Extract unique SPDX license keys from a parsed expression tree."""
    keys: list[str] = []
    seen: set[str] = set()
    for sym in parsed.symbols:
        if isinstance(sym, LicenseWithExceptionSymbol):
            key = str(sym)
        elif isinstance(sym, LicenseSymbol):
            key = sym.key
        else:
            key = str(sym)
        if key not in seen:
            keys.append(key)
            seen.add(key)
    return keys


def _has_deprecated(parsed: Any) -> bool:
    """Check if any license in the expression uses a deprecated SPDX id."""
    for sym in parsed.symbols:
        if hasattr(sym, "is_deprecated") and sym.is_deprecated:
            return True
    return False
