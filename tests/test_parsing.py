"""Tests for license expression parsing adapter."""

from licensestoic.parsing import parse_license_expression, validate_spdx


class TestParseLicenseExpression:
    """Test SPDX expression parsing into structured LicenseExpression objects."""

    def test_simple_spdx_identifier(self):
        result = parse_license_expression("MIT")
        assert result.is_valid_spdx is True
        assert result.spdx_expression == "MIT"
        assert "MIT" in result.identifiers

    def test_compound_and_expression(self):
        result = parse_license_expression("MIT AND Apache-2.0")
        assert result.is_valid_spdx is True
        assert len(result.identifiers) == 2
        assert "MIT" in result.identifiers
        assert "Apache-2.0" in result.identifiers

    def test_compound_or_expression(self):
        result = parse_license_expression("MIT OR GPL-3.0-only")
        assert result.is_valid_spdx is True
        assert len(result.identifiers) == 2

    def test_with_exception(self):
        result = parse_license_expression("GPL-2.0-only WITH Classpath-exception-2.0")
        assert result.is_valid_spdx is True
        assert len(result.identifiers) >= 1

    def test_complex_nested_expression(self):
        result = parse_license_expression("(MIT OR Apache-2.0) AND GPL-3.0-only")
        assert result.is_valid_spdx is True
        assert len(result.identifiers) == 3

    def test_invalid_spdx_preserved_as_raw(self):
        result = parse_license_expression("Some Custom License v2")
        assert result.is_valid_spdx is False
        assert result.raw_text == "Some Custom License v2"
        assert result.identifiers == []

    def test_empty_string(self):
        result = parse_license_expression("")
        assert result.is_valid_spdx is False

    def test_unknown_marker(self):
        result = parse_license_expression("UNKNOWN")
        # UNKNOWN is not a valid SPDX identifier
        assert result.is_valid_spdx is False

    def test_preserves_raw_text(self):
        raw = "MIT"
        result = parse_license_expression(raw)
        assert result.raw_text == raw


class TestValidateSpdx:
    """Test SPDX validation error reporting."""

    def test_valid_expression_no_errors(self):
        errors = validate_spdx("MIT")
        assert errors == []

    def test_invalid_expression_returns_errors(self):
        errors = validate_spdx("NOT_A_LICENSE!!!")
        assert len(errors) > 0

    def test_valid_compound(self):
        errors = validate_spdx("MIT OR Apache-2.0")
        assert errors == []
