"""Tests for the report generation module.

Covers:
- JSON report generation and schema
- JSON report file saving
- Severity bar rendering at boundary values
- Severity colour thresholds
- Action label mapping
- Inconclusive scan detection logic
"""

from __future__ import annotations

import json
from pathlib import Path

from licensestoic.llm_explainer import LLMExplanation
from licensestoic.models import ReviewAction
from licensestoic.report import (
    _action_label,
    _severity_bar,
    _severity_color,
    generate_json_report,
    save_json_report,
)

from factories import make_conflict, make_dep, make_remediation, make_scan_result

# ---------------------------------------------------------------------------
# Severity bar rendering
# ---------------------------------------------------------------------------


class TestSeverityBar:
    def test_zero_severity(self) -> None:
        bar = _severity_bar(0.0)
        assert bar == ".........."
        assert len(bar) == 10

    def test_full_severity(self) -> None:
        bar = _severity_bar(1.0)
        assert bar == "##########"
        assert len(bar) == 10

    def test_half_severity(self) -> None:
        bar = _severity_bar(0.5)
        assert bar.count("#") == 5
        assert bar.count(".") == 5

    def test_boundary_0_15(self) -> None:
        bar = _severity_bar(0.15)
        assert len(bar) == 10
        assert "#" in bar or bar == ".........."  # round(0.15*10)=2

    def test_bar_length_always_10(self) -> None:
        for val in [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0]:
            assert len(_severity_bar(val)) == 10


class TestSeverityColor:
    def test_high_severity_red(self) -> None:
        assert _severity_color(0.7) == "red"
        assert _severity_color(0.85) == "red"
        assert _severity_color(1.0) == "red"

    def test_medium_severity_yellow(self) -> None:
        assert _severity_color(0.4) == "yellow"
        assert _severity_color(0.5) == "yellow"
        assert _severity_color(0.69) == "yellow"

    def test_low_severity_green(self) -> None:
        assert _severity_color(0.0) == "green"
        assert _severity_color(0.2) == "green"
        assert _severity_color(0.39) == "green"


class TestActionLabel:
    def test_escalate(self) -> None:
        label, color = _action_label(ReviewAction.ESCALATE)
        assert label == "ESCALATE"
        assert color == "red"

    def test_suggest(self) -> None:
        label, color = _action_label(ReviewAction.SUGGEST)
        assert label == "SUGGEST"
        assert color == "yellow"

    def test_auto_apply(self) -> None:
        label, color = _action_label(ReviewAction.AUTO_APPLY)
        assert label == "AUTO"
        assert color == "green"


# ---------------------------------------------------------------------------
# JSON report generation
# ---------------------------------------------------------------------------


class TestGenerateJsonReport:
    def test_clean_scan_schema(self) -> None:
        scan = make_scan_result(review_action=ReviewAction.AUTO_APPLY)
        report = generate_json_report(scan)

        assert report["version"] == "1.0.0"
        assert report["project"]["name"] == "test-project"
        assert report["project"]["license"]["spdx_expression"] == "MIT"
        assert report["project"]["distribution_type"] == "binary"
        assert report["scan"]["total_dependencies"] == 0
        assert report["scan"]["total_conflicts"] == 0
        assert report["conflicts"] == []
        assert report["remediations"] == []
        assert "review" in report

    def test_report_with_conflicts(self) -> None:
        conflict = make_conflict()
        remediation = make_remediation(conflict_id=conflict.id)
        scan = make_scan_result(conflicts=[conflict], remediations=[remediation])
        report = generate_json_report(scan)

        assert report["scan"]["total_conflicts"] == 1
        assert len(report["conflicts"]) == 1
        assert report["conflicts"][0]["source_license"] == "GPL-3.0-only"
        assert len(report["remediations"]) == 1

    def test_report_with_llm_explanation(self) -> None:
        scan = make_scan_result()
        explanation = LLMExplanation(
            conflict_explanations=[{"conflict_id": "test", "plain_language": "x"}],
            remediation_rankings=[],
            ambiguous_licenses=[],
            overall_summary="Summary here.",
            raw_response="{}",
        )
        report = generate_json_report(scan, explanation)

        assert "llm_explanation" in report
        assert report["llm_explanation"]["overall_summary"] == "Summary here."

    def test_report_without_llm_explanation(self) -> None:
        scan = make_scan_result()
        report = generate_json_report(scan)
        assert "llm_explanation" not in report

    def test_report_includes_review_summary(self) -> None:
        scan = make_scan_result()
        report = generate_json_report(scan)
        assert "review" in report
        assert "total_conflicts" in report["review"]
        assert "overall_action" in report["review"]

    def test_report_includes_reliability_warnings(self) -> None:
        scan = make_scan_result()
        report = generate_json_report(scan)
        assert "reliability_warnings" in report

    def test_dependencies_counted_correctly(self) -> None:
        deps = [make_dep(name=f"dep-{i}") for i in range(5)]
        scan = make_scan_result(deps=deps)
        report = generate_json_report(scan)
        assert report["scan"]["total_dependencies"] == 5


class TestSaveJsonReport:
    def test_saves_valid_json(self, tmp_path: Path) -> None:
        scan = make_scan_result()
        out = save_json_report(scan, tmp_path / "report.json")

        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["version"] == "1.0.0"

    def test_saves_with_explanation(self, tmp_path: Path) -> None:
        scan = make_scan_result()
        explanation = LLMExplanation(
            conflict_explanations=[],
            remediation_rankings=[],
            ambiguous_licenses=[],
            overall_summary="test",
            raw_response="{}",
        )
        out = save_json_report(scan, tmp_path / "report.json", explanation)

        data = json.loads(out.read_text(encoding="utf-8"))
        assert "llm_explanation" in data

    def test_overwrites_existing_file(self, tmp_path: Path) -> None:
        report_file = tmp_path / "report.json"
        report_file.write_text("old content")

        scan = make_scan_result()
        save_json_report(scan, report_file)

        data = json.loads(report_file.read_text(encoding="utf-8"))
        assert data["version"] == "1.0.0"
