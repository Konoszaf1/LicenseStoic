"""Tests for the human review gate — Layer 5."""

from licensestoic.models import (
    Conflict,
    DistributionType,
    IntegrationType,
    LicenseExpression,
    ReviewAction,
    ScanResult,
)
from licensestoic.review_gate import classify_conflict, determine_review_action


def _make_conflict(severity: float, rule_source: str = "builtin_matrix") -> Conflict:
    return Conflict(
        id=f"conflict-test-{severity}",
        source_node="dep",
        target_node="project",
        source_license="GPL-3.0-only",
        target_license="MIT",
        distribution_type=DistributionType.BINARY,
        integration_type=IntegrationType.STATIC_LINK,
        risk_severity=severity,
        rule_source=rule_source,
        description="Test conflict",
    )


def _make_scan_result(conflicts: list[Conflict]) -> ScanResult:
    return ScanResult(
        project_name="test",
        project_license=LicenseExpression(
            spdx_expression="MIT",
            identifiers=["MIT"],
            is_valid_spdx=True,
        ),
        distribution_type=DistributionType.BINARY,
        dependencies=[],
        conflicts=conflicts,
        remediations=[],
        scan_confidence=1.0,
        review_action=ReviewAction.SUGGEST,
    )


class TestClassifyConflict:
    def test_low_severity_auto_apply(self):
        assert classify_conflict(_make_conflict(0.1)) == ReviewAction.AUTO_APPLY

    def test_medium_severity_suggest(self):
        assert classify_conflict(_make_conflict(0.5)) == ReviewAction.SUGGEST

    def test_high_severity_escalate(self):
        assert classify_conflict(_make_conflict(0.8)) == ReviewAction.ESCALATE

    def test_unknown_rule_source_always_escalates(self):
        assert classify_conflict(_make_conflict(0.1, "not_in_matrix")) == ReviewAction.ESCALATE


class TestDetermineReviewAction:
    def test_no_conflicts_auto_apply(self):
        assert determine_review_action(_make_scan_result([])) == ReviewAction.AUTO_APPLY

    def test_high_severity_escalates(self):
        result = determine_review_action(_make_scan_result([_make_conflict(0.9)]))
        assert result == ReviewAction.ESCALATE

    def test_medium_severity_suggests(self):
        result = determine_review_action(_make_scan_result([_make_conflict(0.5)]))
        assert result == ReviewAction.SUGGEST

    def test_worst_conflict_determines_action(self):
        """Multiple conflicts — worst one wins."""
        conflicts = [_make_conflict(0.1), _make_conflict(0.9)]
        result = determine_review_action(_make_scan_result(conflicts))
        assert result == ReviewAction.ESCALATE


class TestUnknownLicenseEscalation:
    """Unknown license rule source triggers escalation."""

    def test_unknown_license_conflict_escalates(self):
        assert (
            classify_conflict(_make_conflict(0.5, rule_source="unknown_license"))
            == ReviewAction.ESCALATE
        )

    def test_unknown_license_escalates_overall(self):
        conflict = _make_conflict(0.5, rule_source="unknown_license")
        result = determine_review_action(_make_scan_result([conflict]))
        assert result == ReviewAction.ESCALATE
