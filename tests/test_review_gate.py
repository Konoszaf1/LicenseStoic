"""Tests for the human review gate — Layer 5."""

from licensestoic.models import ReviewAction
from licensestoic.review_gate import (
    classify_conflict,
    determine_review_action,
    generate_review_summary,
)

from factories import make_conflict as _make_conflict_factory, make_scan_result


def _make_conflict(severity: float, rule_source: str = "builtin_matrix"):
    return _make_conflict_factory(severity=severity, rule_source=rule_source)


def _make_scan(conflicts):
    return make_scan_result(conflicts=conflicts)


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
        assert determine_review_action(_make_scan([])) == ReviewAction.AUTO_APPLY

    def test_high_severity_escalates(self):
        result = determine_review_action(_make_scan([_make_conflict(0.9)]))
        assert result == ReviewAction.ESCALATE

    def test_medium_severity_suggests(self):
        result = determine_review_action(_make_scan([_make_conflict(0.5)]))
        assert result == ReviewAction.SUGGEST

    def test_worst_conflict_determines_action(self):
        """Multiple conflicts — worst one wins."""
        conflicts = [_make_conflict(0.1), _make_conflict(0.9)]
        result = determine_review_action(_make_scan(conflicts))
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
        result = determine_review_action(_make_scan([conflict]))
        assert result == ReviewAction.ESCALATE


# ---------------------------------------------------------------------------
# generate_review_summary tests (previously 0% coverage)
# ---------------------------------------------------------------------------


class TestGenerateReviewSummary:
    """Test the structured review summary output."""

    def test_empty_conflicts_summary(self):
        scan = _make_scan([])
        summary = generate_review_summary(scan)
        assert summary["total_conflicts"] == 0
        assert summary["escalate"] == []
        assert summary["suggest"] == []
        assert summary["auto_apply"] == []
        assert summary["overall_action"] == "auto_apply"

    def test_high_severity_in_escalate_bucket(self):
        conflict = _make_conflict(0.9)
        scan = _make_scan([conflict])
        summary = generate_review_summary(scan)
        assert len(summary["escalate"]) == 1
        assert summary["escalate"][0]["severity"] == 0.9
        assert summary["overall_action"] == "escalate"

    def test_medium_severity_in_suggest_bucket(self):
        conflict = _make_conflict(0.5)
        scan = _make_scan([conflict])
        summary = generate_review_summary(scan)
        assert len(summary["suggest"]) == 1
        assert summary["overall_action"] == "suggest"

    def test_low_severity_in_auto_bucket(self):
        conflict = _make_conflict(0.1)
        scan = _make_scan([conflict])
        summary = generate_review_summary(scan)
        assert len(summary["auto_apply"]) == 1

    def test_mixed_severities_sorted_into_buckets(self):
        conflicts = [
            _make_conflict(0.1),
            _make_conflict(0.5),
            _make_conflict(0.9),
        ]
        scan = _make_scan(conflicts)
        summary = generate_review_summary(scan)
        assert summary["total_conflicts"] == 3
        assert len(summary["escalate"]) == 1
        assert len(summary["suggest"]) == 1
        assert len(summary["auto_apply"]) == 1

    def test_unknown_rule_source_in_escalate(self):
        conflict = _make_conflict(0.2, rule_source="not_in_matrix")
        scan = _make_scan([conflict])
        summary = generate_review_summary(scan)
        assert len(summary["escalate"]) == 1

    def test_summary_includes_reliability_warnings(self):
        scan = _make_scan([])
        summary = generate_review_summary(scan)
        assert "reliability_warnings" in summary
        assert isinstance(summary["reliability_warnings"], list)

    def test_conflict_entry_structure(self):
        conflict = _make_conflict(0.8)
        scan = _make_scan([conflict])
        summary = generate_review_summary(scan)
        entry = summary["escalate"][0]
        assert "conflict_id" in entry
        assert "source" in entry
        assert "license" in entry
        assert "severity" in entry
        assert "description" in entry
